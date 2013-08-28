#-------------------------------------------------------------------------------
# Jamsi MySQL entity enforcer Class
#-------------------------------------------------------------------------------
# Description
#-------------------------------------------------------------------------------
# This source file is subject to version 2.0 of the Apache License, that is
# bundled with this package in the file LICENSE, and is available through the
# world-wide-web at the following url http://www.apache.org/licenses/LICENSE-2.0
#-------------------------------------------------------------------------------
# Author::    PS  (mailto:ps@jam.si)
# Copyright:: Copyright (c) 2013 PS
# License::   Apache License, Version 2.0
# Version::   0.1.0
#-------------------------------------------------------------------------------

# http://blogs.devart.com/dbforge/how-to-get-a-list-of-permissions-of-mysql-users.html

#
# TO DO: Removing privileges for user (REVOKE ALL PRIVILEGES, GRANT OPTION FROM ...)


require 'open3'

module Jamsi


  #
  # MySQL Class
  #
  class Mysql

    attr_accessor :hostname, :username, :password

    # Privileges and their respected mysql.user columns. This constant Hash is
    # used to map privileges to their columns, but also as a filter list.
    # Privileges not in this Hash are not applied.
    PRIVILEGE_COLS = {
      :create                     => :Create_priv,
      :drop                       => :Drop_priv,
      :"lock tables"              => :Lock_tables_priv,
      :references                 => :References_priv,
      :event                      => :Event_priv,
      :alter                      => :Alter_priv,
      :delete                     => :Delete_priv,
      :index                      => :Index_priv,
      :insert                     => :Insert_priv,
      :select                     => :Select_priv,
      :update                     => :Update_priv,
      :"create temporary tables"  => :Create_tmp_table_priv,
      :trigger                    => :Trigger_priv,
      :"create view"              => :Create_view_priv,
      :"show view"                => :Show_view_priv,
      :"alter routine"            => :Alter_routine_priv,
      :"create routine"           => :Create_routine_priv,
      :"execute"                  => :Execute_priv,
      :file                       => :File_priv,
      :"create tablespace"        => :Create_tablespace_priv,
      :"create user"              => :Create_user_priv,
      :process                    => :Process_priv,
      :reload                     => :Reload_priv,
      :"replication client"       => :Repl_client_priv,
      :"replication slave"        => :Repl_slave_priv,
      :"show databases"           => :Show_db_priv,
      :shutdown                   => :Shutdown_priv,
      :super                      => :Super_priv,
      :proxy                      => nil,
      # USAGE equals 'N' on all columns
      :usage                      => nil,
      # ALL PRIVILEGES equals 'Y' on all columns but GRANT OPTION
      :"all privileges"           => nil,
      # GRANT OPTION is not included in ALL PRIVILEGES
      :"grant option"             => :Grant_priv,
    }


    def initialize (hostname = 'localhost', username = 'root', password = '')

      @hostname = hostname
      @username = username
      @password = password

      # Cached values of exists? queries. If exists? method has already run on
      # certain data, create method uses cached value, instead of running exists?
      # again.
      @exists_hash = Hash.new

      # Notice Hash, that gets filled with create and modify entity messages
      # and gets put out in the end.
      @create_notice = Hash.new
      @create_notice[:databases_created] = String.new
      @create_notice[:databases_modified] = String.new
      @create_notice[:tables_created] = String.new
      @create_notice[:tables_modified] = String.new
      @create_notice[:columns_created] = String.new
      @create_notice[:columns_modified] = String.new
      @create_notice[:indexes_created] = String.new
      @create_notice[:indexes_modified] = String.new
      @create_notice[:users_created] = String.new
      @create_notice[:users_modified] = String.new

    end



    # Verifies if all entities of a manifest specified in parameter_hash exist
    # in the database and parameters match. Returns true if ALL entities exist
    # and ALL parameters match.
    #
    # Populates @database, @tables, @columns, @indexes, @users, @users_grant_<scope>
    # Array with validated entities (Hashes)
    #
    # Params:
    # +parameter_hash+:: +Hash+ object representing MySQL entities
    def exists? (parameter_hash)

      # Validate parameters, before proceeding
      validate_params parameter_hash

      exists = true

      if @databases.length > 0
        if databases_exist? == false
          exists = false
        end
      end

      if @tables.length > 0
        if tables_exist? == false
          exists = false
        end
      end

      if @columns.length > 0
        if columns_exist? == false
          exists = false
        end
      end

      if @indexes.length > 0
        if indexes_exist? == false
          exists = false
        end
      end

      if @users_global.length > 0
        if users_global_exist? == false
          exists = false
        end
      end
      if @users_database.length > 0
        if users_database_exist? == false
          exists = false
        end
      end
      if @users_table.length > 0
        if users_table_exist? == false
          exists = false
        end
      end
      if @users_column.length > 0
        if users_column_exist? == false
          exists = false
        end
      end
      if @users_procedure.length > 0
        if users_procedure_exist? == false
          exists = false
        end
      end

      @exists_hash[parameter_hash.hash] = exists

      return exists

    end



    # Creates or modifies the entities of a manifest specified in parameter_hash
    # if they do not exist yet. Entity existence is checked in either @exist_hash
    # cache, or via exists? method if no cache exists.
    #
    # Params:
    # +parameter_hash+:: +Hash+ object representing MySQL entities
    def create (parameter_hash)
      # Cached values of exists? queries. If exists? method has already run on
      # certain data, enforce! method uses cached value, instead of running exists?
      # again.
      if @exists_hash.has_key?(parameter_hash.hash)
        exists = @exists_hash[parameter_hash.hash]
      else
        exists = exists?
      end

      if exists == true
        notice "All entities of the manifest already exist in the database. No changes made."
        return
      end


      # Add missing databases
      if @databases_new.kind_of?(Array) && @databases_new.length > 0
        databases_create
      end

      # Modify databases to match expected parameters
      if @databases_modify.kind_of?(Array) && @databases_modify.length > 0
        databases_modify
      end

      # Add missing tables
      if @tables_new.kind_of?(Array) && @tables_new.length > 0
        tables_create
      end

      # Modify tables to match expected parameters
      if (@tables_modify.kind_of?(Array) && @tables_modify.length > 0) ||
         (@columns_new.kind_of?(Array) && @columns_new.length > 0) ||
         (@columns_modify.kind_of?(Array) && @columns_modify.length > 0) ||
         (@indexes_new.kind_of?(Array) && @indexes_new.length > 0) ||
         (@indexes_modify.kind_of?(Array) && @indexes_modify.length > 0)
        tables_modify
      end

      # Add missing users with global privileges
      if @users_global_new.kind_of?(Array) && @users_global_new.length > 0
        users_global_create
      end

      # Modify users with global privileges
      if @users_global_modify.kind_of?(Array) && @users_global_modify.length > 0
        users_global_modify
      end

      # Add missing users with database privileges
      if @users_database_new.kind_of?(Array) && @users_database_new.length > 0
        users_database_create
      end

      # Modify users with database privileges
      if @users_database_modify.kind_of?(Array) && @users_database_modify.length > 0
        users_database_modify
      end

      # Add missing users with table privileges
      if @users_table_new.kind_of?(Array) && @users_table_new.length > 0
        users_table_create
      end

      # Modify users with table privileges
      if (@users_table_modify.kind_of?(Array) && @users_table_modify.length > 0) ||
         (@users_column_new.kind_of?(Array) && @users_column_new.length > 0) ||
         (@users_column_modify.kind_of?(Array) && @users_column_modify.length > 0)
        p @users_table_modify
        p @users_column_new
        p @users_column_modify
        users_table_modify
      end

      # Add missing users with procedure privileges
      if @users_procedure_new.kind_of?(Array) && @users_procedure_new.length > 0
        users_procedure_create
      end

      # Modify users with procedure privileges
      if @users_procedure_modify.kind_of?(Array) && @users_procedure_modify.length > 0
        users_procedure_modify
      end

      cn = create_notice_to_s @create_notice
      if cn.length > 0
        notice cn
      end

    end



    #
    # Prints out notice level messages
    #
    def notice (str)
      puts "\e[32m#{str.to_s}\e[0m"
    end
    private :notice



    #
    # Prints out warning level messages
    #
    def warning (str)
      puts "\e[33m#{str.to_s}\e[0m"
    end
    private :warning



    #
    # Prints out error level messages
    #
    def error (str)
      puts "\e[31m#{str.to_s}\e[0m"
      exit
    end
    private :error



    #
    # Converts @create_notice to properly ordered Hash
    # (ruby 1.8 doesn't seem to keep Hash order)
    #
    def create_notice_to_s (hash)

      str = ''
      if @create_notice[:databases_created].length > 0
        str += "\nDatabases created:#{@create_notice[:databases_created]}"
      end
      if @create_notice[:databases_modified].length > 0
        str += "\nDatabases modified:#{@create_notice[:databases_modified]}"
      end
      if @create_notice[:tables_created].length > 0
        str += "\nTables created:#{@create_notice[:tables_created]}"
      end
      if @create_notice[:tables_modified].length > 0
        str += "\nTables modified:#{@create_notice[:tables_modified]}"
      end
      if @create_notice[:columns_created].length > 0
        str += "\nColumns created:#{@create_notice[:columns_created]}"
      end
      if @create_notice[:columns_modified].length > 0
        str += "\nColumns modified:#{@create_notice[:columns_modified]}"
      end
      if @create_notice[:indexes_created].length > 0
        str += "\nIndexes created:#{@create_notice[:indexes_created]}"
      end
      if @create_notice[:indexes_modified].length > 0
        str += "\nIndexes modified:#{@create_notice[:indexes_modified]}"
      end
      if @create_notice[:users_created].length > 0
        str += "\nUsers created:#{@create_notice[:users_created]}"
      end
      if @create_notice[:users_modified].length > 0
        str += "\nUsers modified:#{@create_notice[:users_modified]}"
      end

      return str

    end
    private :create_notice_to_s



    #
    # Performs MySQL query using CLI mysql command
    #
    # Returns Array of Hashes (rows)
    #
    def mysql_cli_query (query)

      # replace new lines in the query with spaces
      query.gsub!("\n", " ")
      # remove multiple spaces
      query.gsub!(/\s\s+/,' ')

      unescaped_query = query.dup

      # escape double quotes
      query.gsub!(/"/, "\\\\\"")
      # escape backticks
      query.gsub!("`", "\\\\\`")
      

      # concat CLI command
      command = "mysql -h #{@hostname} -u #{@username} -p#{@password} -e \"#{query}\""

      rows = Array.new

      # perform the command, catch possible errors and put result lines in an
      # Array
      Open3.popen3(command) {|stdin, stdout, stderr, wait_thr|

        while line = stderr.gets
          notice create_notice_to_s @create_notice
          error "Query: " + unescaped_query + "\nreturned error: " + line
        end

        while line = stdout.gets
          rows.push(line.gsub("\n", ""))
        end

      }

      # Loop through result and build an Array of Hashes where each Hash
      # represents a result row and consists of column_name => value pairs.
      result_array = Array.new
      column_index = Array.new

      rows.each_with_index do |row, i|
        columns = row.split("\t")
        if i == 0
          column_index = columns
        else
          row_hash = Hash.new
          columns.each_with_index do |column, j|
            row_hash[column_index[j].to_sym] = column
          end
          result_array.push(row_hash)
        end
      end

      return result_array

    end
    private :mysql_cli_query



    #
    # Returns
    #
    def show_privileges (context = :all)

      unless @show_privileges.kind_of?(Hash)

        @show_privileges = Hash.new
        @show_privileges[:all]  = Array.new
        @show_privileges[:global] = Array.new
        @show_privileges[:database] = Array.new
        @show_privileges[:table] = Array.new
        @show_privileges[:procedure] = Array.new

        # We can't get column privileges using SHOW PRIVILEGES commands, so
        # doing it by hand
        @show_privileges[:column] = [:select, :insert, :update]

        result = mysql_cli_query 'SHOW PRIVILEGES'

        result.each do |row|
          @show_privileges[:all].push(row[:Privilege].to_sym)
          contexts = row[:Context].split(/,\s+|,/)
          contexts.each do |con|
            if con.downcase.to_sym == :"server admin"
              @show_privileges[:global].push(row[:Privilege].downcase.to_sym)
            elsif con.downcase.to_sym == :databases
              @show_privileges[:database].push(row[:Privilege].downcase.to_sym)
            elsif con.downcase.to_sym == :tables
              @show_privileges[:table].push(row[:Privilege].downcase.to_sym)
            elsif con.downcase.to_sym == :procedures
              @show_privileges[:procedure].push(row[:Privilege].downcase.to_sym)
            end
          end

        end

      end

      return @show_privileges[context]

    end
    private :show_privileges



    #
    # Validates input parameters and adds missing parameters where needed
    #
    # Populates @database, @tables, @columns, @indexes, @users, @users_grant_<scope>
    # Array with validated entities (Hashes)
    #
    def validate_params (parameter_hash)

      #
      # Databases
      #
      @databases = parameter_hash[:databases]


      #
      # Tables
      #
      @tables = parameter_hash[:tables]
      @tables.each do |table|

        table_has_columns = false
        parameter_hash[:columns].each do |column|
          if table[:database] == column[:database] && table[:name] == column[:table]
            table_has_columns = true
            break
          end
        end
        if table_has_columns == false
          error "Table #{table[:database]}.#{table[:name]} has no columns defined."
        end

        if table.has_key?(:collation)
          unless table.has_key?(:character_set)
            table[:character_set] = table[:collation].split(/_/, 2)[0]
            warning "Table #{table[:database]}.#{table[:name]} COLLATION defined, but no CHARACTER SET. Assuming '#{table[:character_set]}'."
          end
        end
      end


      #
      # Indexes
      #
      @indexes = parameter_hash[:indexes]

      @indexes.each do |index|
        if index.has_key?(:column) && !index.has_key?(:columns)
          index[:columns] = index[:column]
        end

        if index[:columns].kind_of?(String)
          index[:columns] = index[:columns].split(/,\s+|,/)
        elsif index[:columns].kind_of?(Array) && index[:columns].length > 0
          # all is well
        else
          error "Index '#{index[:database]}.#{index[:table]}.#{index[:name]}' has no 'columns' parameter defined."
        end

        if index.has_key?(:type)
          if index[:type].to_s.downcase[0,3] == 'pri'
            index[:type] = :primary
          elsif index[:type].to_s.downcase[0,3] == 'uni'
            index[:type] = :unique
          elsif index[:type].to_s.downcase == 'index' || index[:type].to_s.downcase == 'mul'
            index[:type] = :index
          else
            error "Index '#{index[:database]}.#{index[:table]}.#{index[:name]}' type is wrong: '#{index[:type]}'"
          end
        else
          index[:type] = :index
        end

        # If manifest does not specify index name, we will generate one
        if index.has_key?(:name)
          index[:assigned_name] = index[:name]
        elsif index[:type] == :primary
          index[:assigned_name] = 'PRIMARY'
        else
          index[:assigned_name] = index[:columns][0] + '_' + index[:type].to_s.upcase
        end
      end


      #
      # Columns
      #
      @columns = parameter_hash[:columns]

      @columns.each do |column|

        if column.has_key?(:null)
          if column[:null] == 'YES' || column[:null] == 'true'
            column[:null] = :yes
          elsif column[:null] == 'NO' || column[:null] == 'false'
            column[:null] = :no
          else
            warning "Column '#{column[:database]}.#{column[:table]}.#{column[:name]}' 'null' parameter is wrong: '#{column[:null]}', omitting."
            column.delete(:null)
          end
        end

        if column.has_key?(:default_value)
          if column[:default_value].to_s.downcase == 'null'
            column[:default_value] = :null
          end
        end

        # We accept index parameter as part of column Hash, but this is
        # really just a shortcut to specify an index. Therefore we collect those indexes
        # and add them to @indexes Array.
        if column.has_key?(:index)

          if column[:index].to_s.downcase[0,3] == 'pri'
            column[:index] = :primary
          elsif column[:index].to_s.downcase[0,3] == 'uni'
            column[:index] = :unique
          elsif column[:index].to_s.downcase == 'index' || column[:index].to_s.downcase == 'mul'
            column[:index] = :index
          else
            error "Column '#{column[:database]}.#{column[:table]}.#{column[:name]}' 'index' parameter is wrong: '#{column[:index]}'"
          end

          # If we specify an index key for the column, that already has an index
          # specified in @indexes, we throw an error.
          column_key_already_in_indexes = false
          @indexes.each do |index|
            if index[:database] == column[:database] && index[:table] == column[:table]
              if (index.has_key?(:columns) && index[:columns].include?(column[:name]))
                 column_key_already_in_indexes = true
                 warning "Column '#{column[:database]}.#{column[:table]}.#{column[:name]}' index already defined in indexes array, ignoring column's 'index' parameter."
              end
            end
          end

          if column_key_already_in_indexes == false
            index = Hash.new
            index[:database] = column[:database]
            index[:table] = column[:table]
            index[:columns] = [ column[:name] ]
            index[:type] = column[:index]
            if index[:type] == :primary
              index[:assigned_name] = 'PRIMARY'
            else
              index[:assigned_name] = column[:name] + '_' + index[:type].to_s.upcase
            end
            @indexes.push(index)
          end
        end

        if column.has_key?(:extra)         
          if column[:extra].downcase == 'auto_increment'
            column[:extra] = :auto_increment
            # AUTO_INCREMENT columns can not be NULL
            if column.has_key?(:null) && column[:null] == :yes
              error "Column '#{column[:database]}.#{column[:table]}.#{column[:name]}' is defined as AUTO_INCREMENT, 'null' parameter can not be 'YES'."
            end
            # AUTO_INCREMENT can only be applied to columns with an index.
            column_has_index = false
            @indexes.each do |index|
              if index[:database] == column[:database] && index[:table] == column[:table]
                if (index.has_key?(:columns) && index[:columns].include?(column[:name]))
                   column_has_index = true
                end
              end
            end
            if column_has_index == false
              error "Column '#{column[:database]}.#{column[:table]}.#{column[:name]}' is defined as AUTO_INCREMENT, but has no index defined."
            end

            # Default value can not be specified together with AUTO_INCREMENT
            if column.has_key?(:default_value)
              error "Column '#{column[:database]}.#{column[:table]}.#{column[:name]}' is defined as AUTO_INCREMENT, it can not have 'dafault_value'."
            end
          end
        end
      end


      #
      # Users
      #
      @users_global = Array.new
      @users_database = Array.new
      @users_table = Array.new
      @users_column = Array.new
      @users_procedure = Array.new
      users = Array.new

      # Each user can have multiple hosts specified and multiple privileges, but
      # from MySQL's point of view each user-host-privilege combination is presented
      # as a separate entity, so we will split those combinations now and fill
      # @users_<scope> variables with those user-host-privilege entities
      parameter_hash[:users].each do |user|
        unless user.has_key?(:name)
          error "User has no 'name' parameter defined."
        end

        if user.has_key?(:host) && !user.has_key?(:hosts)
          user[:hosts] = user[:host]
        end

        if user[:hosts].kind_of?(String)
          user[:hosts] = user[:hosts].split(/,\s+|,/)
        elsif user[:hosts].kind_of?(Array) && user[:hosts].length > 0
          # all is well
        else
          # If user provides no hosts, we assume 'localhost'
          user[:hosts] = [ :localhost ]
        end

        unless user.has_key?(:privileges) && user[:privileges].kind_of?(Array) && user[:privileges].length > 0
          user[:privileges] = [{ :scope => :global, :type => [] }]
          warning "User #{user[:name]}@#{user[:host]} has no 'privileges' parameter defined."
        end

        user[:hosts].each do |host|
          user[:privileges].each do |privilege|
            user_row = Hash.new
            user_row[:name] = user[:name]
            user_row[:host] = host
            if user.has_key?(:password)
              user_row[:password] = user[:password]
            elsif user.has_key?(:password_encrypted)
              user_row[:password_encrypted] = user[:password_encrypted]
            end

            if privilege.has_key?(:scope)
              if privilege[:scope].to_s.downcase == 'global'
                user_row[:privilege_scope] = :global
              elsif privilege[:scope].to_s.downcase == 'database'
                user_row[:privilege_scope] = :database
              elsif privilege[:scope].to_s.downcase == 'table'
                user_row[:privilege_scope] = :table
              elsif privilege[:scope].to_s.downcase == 'column'
                user_row[:privilege_scope] = :column
              elsif privilege[:scope].to_s.downcase == 'procedure'
                user_row[:privilege_scope] = :procedure
              end
            end

            # If there is no scope defined, we can guess it from the other parameters
            unless user_row.has_key?(:privilege_scope)
              if privilege.has_key?(:procedure)
                user_row[:privilege_scope] = :procedure
              elsif privilege.has_key?(:column)
                user_row[:privilege_scope] = :column
              elsif privilege.has_key?(:table)
                user_row[:privilege_scope] = :table
              elsif privilege.has_key?(:database)
                user_row[:privilege_scope] = :database
              else
                user_row[:privilege_scope] = :global
              end
            end

            if privilege.has_key?(:type) && privilege[:type].kind_of?(String)
              if privilege[:type].to_s.downcase == 'all' || privilege[:type].to_s.downcase == 'all privileges'
                user_row[:privilege_type] = [ :"all privileges" ]
              else
                user_row[:privilege_type] = privilege[:type].split(/,\s+|,/)
              end
            elsif privilege[:type].kind_of?(Array) && privilege[:type].length > 0
              user_row[:privilege_type] = privilege[:type]
            else
              warning "User #{user[:name]}@#{user[:host]} has no privileges 'type' parameter defined. Assuming 'USAGE'"
              user_row[:privilege_type] = [ :usage ]
            end

            # Filter types that are not in PRIVILEGE_COLS Hash, downcase and
            # symbolize all type strings
            privilege_type = Array.new
            user_row[:privilege_type].each do |type|
              if type.to_s.downcase == 'all' || type.to_s.downcase == 'all privileges'
                privilege_type.push :"all privileges"
              elsif type.to_s.downcase == 'grant' || type.to_s.downcase == 'grant option'
                privilege_type.push :"grant option"
              else   
                type_in_privilege_cols = false
                PRIVILEGE_COLS.each do |key, value|
                  if key == type.to_s.downcase.to_sym
                    type_in_privilege_cols = true
                  end
                end
                if type_in_privilege_cols == true
                  new_type = type.to_s.downcase.to_sym
                  privilege_type.push(new_type)
                else
                  warning "User #{user[:name]}@#{user[:host]} #{privilege[:scope]} privilege 'type' '#{type}' is not permited. Ignoring."
                end
              end
            end
            user_row[:privilege_type] = privilege_type

            if privilege.has_key?(:database)
              user_row[:privilege_database] = privilege[:database]
            end
            if privilege.has_key?(:table)
              user_row[:privilege_table] = privilege[:table]
            end
            if privilege.has_key?(:column)
              user_row[:privilege_column] = privilege[:column]
            end
            if privilege.has_key?(:procedure)
              user_row[:privilege_procedure] = privilege[:procedure]
            end

            if host == '%'
              user_row[:escaped_host] = '\%'
            else
              user_row[:escaped_host] = host
            end

            if user_row[:privilege_type].length > 0
              users.push(user_row)
              if user_row[:privilege_scope] == :global
                @users_global.push(user_row)
              elsif user_row[:privilege_scope] == :database
                @users_database.push(user_row)
              elsif user_row[:privilege_scope] == :table
                @users_table.push(user_row)
              elsif user_row[:privilege_scope] == :column
                @users_column.push(user_row)
              elsif user_row[:privilege_scope] == :procedure
                @users_procedure.push(user_row)
              end
            end

          end
        end

        # Each user has some kind of global privileges, even if there are none. If
        # manifest Hash has no :scope => 'global' privilege, we will add one with
        # no (:usage) rights.
        users.each do |user|
          user_has_global_privileges = false
          @users_global.each do |user_global|
            if user[:name] == user_global[:name] && user[:host] == user_global[:host]
              user_has_global_privileges = true
              break
            end
          end

          if user_has_global_privileges == false
            u = user.dup
            u[:privilege_scope] = :global
            u[:privilege_type] = [ :usage ]
            @users_global.push(u)
          end
        end

        # Table privileges apply to all columns in a given table. If user has
        # ALL PRIVILEGES on a table, there is no need to applie any additional
        # column privileges.
        @users_column.delete_if do |user_column|
          table_has_all_privileges = false
          @users_table.each do |user_table|
            if user_table[:name] == user_column[:name] && user_table[:host] == user_column[:host] && user_table[:privilege_database] == user_column[:privilege_database] && user_table[:privilege_table] == user_column[:privilege_table]
              if user_table[:privilege_type].include? :"all privileges"
                table_has_all_privileges = true
                break
              end
            end
          end

          if table_has_all_privileges == true
            warning "User #{user_column[:name]}@#{user_column[:host]} has ALL PRIVILEGES on table #{user_column[:privilege_database]}.#{user_column[:privilege_table]}, skipping privileges on column #{user_column[:privilege_column]}."
            true
          end
        end

      end

    end
    private :validate_params



    #
    # Verifies if provided databases exist and have the same properties as
    # expected by the manifest
    #
    # Populates @databases_new and @databases_modify Arrays
    #
    # Returns true if all databases exist and have provided parameters
    #
    def databases_exist?

      @databases_new = Array.new
      @databases_modify = Array.new

      query = " SELECT  SCHEMA_NAME as db,
                          IF (1 = 0"

      @databases.each do |database|
        query += "  OR (    SCHEMA_NAME     LIKE '#{database[:name]}'"

        if database.has_key?(:character_set)
          query += "    AND DEFAULT_CHARACTER_SET_NAME LIKE '#{database[:character_set]}'"
        end

        if database.has_key?(:collation)
          query += "    AND DEFAULT_COLLATION_NAME LIKE '#{database[:collation]}'"
        end

        query += "  )"
      end

      query += "  , TRUE, FALSE) as database_exists
                  FROM INFORMATION_SCHEMA.SCHEMATA
                  WHERE 1 = 0"

      @databases.each do |database|
        query += "  OR SCHEMA_NAME  LIKE '#{database[:name]}'"
      end

      result_databases = mysql_cli_query query


      # Compare Array of returned results with Array of manifest databases and
      # fill @databases_new and @databases_modify Arrays to be used by create
      # method
      @databases_new = @databases.dup

      @databases.each do |database|
        result_databases.each do |result_database|
          if database[:name] == result_database[:db]
            @databases_new.delete(database)
            if result_database[:database_exists] == 0.to_s
              @databases_modify.push(database)
            end
          end
        end
      end

      if @databases_new.length > 0 || @databases_modify.length > 0
        return false
      else
        return true
      end

    end
    private :databases_exist?



    #
    # Creates databases that do not exist yet
    #
    def databases_create

      @databases_new.each do |database|

        @create_notice[:databases_created] += "\n  #{database[:name]}"

        query = " CREATE DATABASE `#{database[:name]}`"

        if database.has_key?(:character_set)
          query += "  CHARACTER SET = #{database[:character_set]}"
        end

        if database.has_key?(:collation)
          query += "  COLLATE = #{database[:collation]}"
        end

        mysql_cli_query query

      end

    end
    private :databases_create



    #
    # Modifies databases to match properties specified in the manifest
    #
    def databases_modify

      @databases_modify.each do |database|

        @create_notice[:databases_modified] += "\n  #{database[:name]}"

        query = " ALTER  DATABASE `#{database[:name]}`"

        if database.has_key?(:character_set)
          query += "  CHARACTER SET = #{database[:character_set]}"
        end

        if database.has_key?(:collation)
          query += "  COLLATE = #{database[:collation]}"
        end

        mysql_cli_query query

      end

    end
    private :databases_modify



    #
    # Verifies if provided tables exist and have the same properties as expected
    # by the manifest
    #
    # Populates @tables_new and @tables_modify
    #
    # Returns true if all tables exist and have provided parameters
    #
    def tables_exist?

      @tables_new = Array.new
      @tables_modify = Array.new

      query = " SELECT  TABLE_SCHEMA as db, TABLE_NAME as tb,
                            IF (1 = 0"

      @tables.each do |table|
        query += "  OR (    TABLE_SCHEMA    LIKE '#{table[:database]}'
                            AND TABLE_NAME      LIKE '#{table[:name]}'"

        if table.has_key?(:engine)
          query += "    AND ENGINE          LIKE '#{table[:engine]}'"
        end

        if table.has_key?(:collation)
          query += "    AND TABLE_COLLATION LIKE '#{table[:collation]}'"
        end

        query += "  )"
      end

      query += "  , TRUE, FALSE) as table_exists
                    FROM INFORMATION_SCHEMA.TABLES
                    WHERE 1 = 0"

      @tables.each do |table|
        query += "  OR (    TABLE_SCHEMA  LIKE '#{table[:database]}'
                            AND TABLE_NAME    LIKE '#{table[:name]}'
                        )"
      end

      result_tables = mysql_cli_query query


      # Compare Array of returned results with Array of tables we demand to be
      # present, and fill @tables_new and @tables_modify Arrays to be used by
      # create

      @tables_new = @tables.dup

      @tables.each do |table|
        result_tables.each do |result_table|
          if table[:name] == result_table[:tb] && table[:database] == result_table[:db]
            @tables_new.delete(table)
            if result_table[:table_exists] == 0.to_s
              @tables_modify.push(table)
            end
          end
        end
      end

      if @tables_new.length > 0 || @tables_modify.length > 0
        return false
      else
        return true
      end

    end
    private :tables_exist?



    #
    # Creates tables that do not exist yet, add all columns and indexes
    #
    def tables_create

      @tables_new.each do |table|

        @create_notice[:tables_created] += "\n  #{table[:database]}.#{table[:name]}"

        query = " CREATE TABLE `#{table[:database]}`.`#{table[:name]}` ("

        #
        # Columns
        #
        period = ''
        @columns_new.each do |column|

          unless column[:database] == table[:database] && column[:table] == table[:name]
            next
          end

          @create_notice[:columns_created] += "\n  #{column[:database]}.#{column[:table]}.#{column[:name]}"

          query += period + "   `#{column[:name]}`"

          if column.has_key?(:type)
            query += "    #{column[:type]}"
          end

          if column.has_key?(:null)
            if column[:null] == :yes
              query += "  NULL"
            else
              query += "  NOT NULL"
            end
          end

          if column.has_key?(:default_value)
            if column[:default_value] == :null
              query += "  DEFAULT NULL"
            else
              query += "  DEFAULT '#{column[:default_value]}'"
            end
          end

          if column.has_key?(:extra)
            if column[:extra] == :auto_increment
              query += "  AUTO_INCREMENT"
            end
          end

          period = ', '

        end

        #
        # Indexes
        #
        @indexes_new.each do |index|

          unless index[:database] == table[:database] && index[:table] == table[:name]
            next
          end

          @create_notice[:columns_created] += "\n  #{index[:database]}.#{index[:table]}.#{index[:assigned_name]} (#{index[:columns].join(", ")})"

          if index[:type] == :primary
            query += ",   PRIMARY KEY (`#{index[:columns].join("`, `")}`)"
          elsif index[:type] == :unique
            query += ",   UNIQUE INDEX `#{index[:assigned_name]}` (`#{index[:columns].join("`, `")}`)"
          elsif index[:type] == :index
            query += ",   INDEX `#{index[:assigned_name]}` (`#{index[:columns].join("`, `")}`)"
          end

        end


        query += " )"

        if table.has_key?(:engine)
          query += "  ENGINE = #{table[:engine]}"
        end

        if table.has_key?(:character_set)
          query += "  CHARACTER SET = #{table[:character_set]}"
        end

        if table.has_key?(:collation)
          query += "  COLLATE = #{table[:collation]}"
        end

        mysql_cli_query query

      end

    end
    private :tables_create



    #
    # Modifies tables, columns and indexes to match properties specified in the
    # manifest.
    #
    def tables_modify

      # Obviously we modify all tables in @tables_modify, but we also need to
      # modify tables, which are not in @tables_modify and @tables_new Arrays,
      # but their columns are in @columns_new and @columns_modify Arrays and
      # their indexes are in @indexes_new and @indexes_modify Arrays.
      @columns_new.each do |column|
        add_column_to_tables_modify = true
        @tables_new.each do |table|
          if column[:database] == table[:database] && column[:table] == table[:name]
            add_column_to_tables_modify = false
            break
          end
        end
        @tables_modify.each do |table|
          if column[:database] == table[:database] && column[:table] == table[:name]
            add_column_to_tables_modify = false
            break
          end
        end
        if add_column_to_tables_modify == true
          @tables_modify.push({ :database => column[:database], :name => column[:table]})
        end
      end
      @columns_modify.each do |column|
        add_column_to_tables_modify = true
        @tables_new.each do |table|
          if column[:database] == table[:database] && column[:table] == table[:name]
            add_column_to_tables_modify = false
            break
          end
        end
        @tables_modify.each do |table|
          if column[:database] == table[:database] && column[:table] == table[:name]
            add_column_to_tables_modify = false
            break
          end
        end
        if add_column_to_tables_modify == true
          @tables_modify.push({ :database => column[:database], :name => column[:table]})
        end
      end
      @indexes_new.each do |index|
        add_index_to_tables_modify = true
        @tables_new.each do |table|
          if index[:database] == table[:database] && index[:table] == table[:name]
            add_index_to_tables_modify = false
            break
          end
        end
        @tables_modify.each do |table|
          if index[:database] == table[:database] && index[:table] == table[:name]
            add_index_to_tables_modify = false
            break
          end
        end
        if add_index_to_tables_modify == true
          @tables_modify.push({ :database => column[:database], :name => column[:table]})
        end
      end
      @indexes_modify.each do |index|
        add_index_to_tables_modify = true
        @tables_new.each do |table|
          if index[:database] == table[:database] && index[:table] == table[:name]
            add_index_to_tables_modify = false
            break
          end
        end
        @tables_modify.each do |table|
          if index[:database] == table[:database] && index[:table] == table[:name]
            add_index_to_tables_modify = false
            break
          end
        end
        if add_index_to_tables_modify == true
          @tables_modify.push({ :database => index[:database], :name => index[:table]})
        end
      end

      @tables_modify.each do |table|

        @create_notice[:tables_modified] += "\n  #{table[:database]}.#{table[:name]}"

        query = " ALTER  TABLE `#{table[:database]}`.`#{table[:name]}`"

        period = ''


        #
        # Columns create
        #
        @columns_new.each do |column|

          unless column[:database] == table[:database] && column[:table] == table[:name]
            next
          end

          @create_notice[:columns_created] += "\n  #{column[:database]}.#{column[:table]}.#{column[:name]}"

          query += period + "   ADD COLUMN `#{column[:name]}`"

          if column.has_key?(:type)
            query += "    #{column[:type]}"
          end

          if column.has_key?(:null)
            if column[:null] == :yes
              query += "  NULL"
            else
              query += "  NOT NULL"
            end
          end

          if column.has_key?(:default_value)
            if column[:default_value] == :null
              query += "  DEFAULT NULL"
            else
              query += "  DEFAULT '#{column[:default_value]}'"
            end
          end

          if column.has_key?(:extra)
            if column[:extra] == :auto_increment
              query += "  AUTO_INCREMENT"
            end
          end

          period = ', '

        end


        #
        # Columns modify
        #
        @columns_modify.each do |column|

          unless column[:database] == table[:database] && column[:table] == table[:name]
            next
          end

          @create_notice[:columns_modified] += "\n  #{column[:database]}.#{column[:table]}.#{column[:name]}"

          query += period + "   CHANGE COLUMN  `#{column[:name]}` `#{column[:name]}`"

          # Type is specified by the manifest
          if column.has_key?(:type)
            query += "    #{column[:type]}"
            # Type is not specified by the manifest, but has to be provided, so we
            # use the current type of the column
          else
            query += "    #{column[:original_type]}"
          end

          if column.has_key?(:null)
            if column[:null] == :yes
              query += "  NULL"
            else
              query += "  NOT NULL"
            end
          end

          if column.has_key?(:default_value)
            if column[:default_value] == :null
              query += "  DEFAULT NULL"
            else
              query += "  DEFAULT '#{column[:default_value]}'"
            end
          end

          if column.has_key?(:extra)
            if column[:extra] == :auto_increment
              query += "  AUTO_INCREMENT"
            end
          end

          period = ', '

        end


        #
        # Indexes create
        #
        @indexes_new.each do |index|

          unless index[:database] == table[:database] && index[:table] == table[:name]
            next
          end

          @create_notice[:indexes_created] += "\n  #{index[:database]}.#{index[:table]}.#{index[:assigned_name]} (#{index[:columns].join(", ")})"

          if index[:type] == :primary
            query += period + "   ADD PRIMARY KEY (`#{index[:columns].join("`, `")}`)"
            period = ', '
          elsif index[:type] == :unique
            query += period + "   ADD UNIQUE INDEX `#{index[:assigned_name]}` (`#{index[:columns].join("`, `")}`)"
            period = ', '
          elsif index[:type] == :index
            query += period + "   ADD INDEX `#{index[:assigned_name]}` (`#{index[:columns].join("`, `")}`)"
            period = ', '
          end

        end


        #
        # Indexes modify
        #
        @indexes_modify.each do |index|

          unless index[:database] == table[:database] && index[:table] == table[:name]
            next
          end

          @create_notice[:indexes_modified] += "\n  #{index[:database]}.#{index[:table]}.#{index[:assigned_name]} (#{index[:columns].join(", ")})"

          # If index with the same name already exists, drop it
          if index[:type] == :primary && index[:name_exists] == true
            query += period + "    DROP PRIMARY KEY"
            period = ', '
          elsif index[:name_exists] == true
            query += period + "    DROP INDEX `#{index[:assigned_name]}`"
            period = ', '
          end

          # If we are renaming the index, drop the old one
          if index.has_key?(:old_name) && index[:old_name] != index[:assigned_name]
            query += period + "    DROP INDEX `#{index[:old_name]}`"
            period = ', '
          end

          if index[:type] == :primary
            query += period + "   ADD PRIMARY KEY (`#{index[:columns].join("`, `")}`)"
            period = ', '
          elsif index[:type] == :unique
            query += period + "   ADD UNIQUE INDEX `#{index[:assigned_name]}` (`#{index[:columns].join("`, `")}`)"
            period = ', '
          elsif index[:type] == :index
            query += period + "   ADD INDEX `#{index[:assigned_name]}` (`#{index[:columns].join("`, `")}`)"
            period = ', '
          end

        end



        if table.has_key?(:character_set)
          query += period + "  CHARACTER SET = #{table[:character_set]}"
          if table.has_key?(:collation)
            query += ",  COLLATE = #{table[:collation]}"
          end
          period = ', '
        end

        if table.has_key?(:engine)
          query += period + "  ENGINE = #{table[:engine]}"
          period = ', '
        end

        mysql_cli_query query

      end

    end
    private :tables_modify


    #
    # Verifies if provided columns exist and have the same properties as expected
    # by the manifest
    #
    # Populates @columns_new and @columns_modify
    #
    # Returns true if all columns exist and have provided parameters
    #
    def columns_exist?

      @columns_new = Array.new
      @columns_modify = Array.new

      query = " SELECT  TABLE_SCHEMA as db, TABLE_NAME as tb, COLUMN_NAME as col, COLUMN_TYPE as type,
                          IF (1 = 0"

      @columns.each do |column|
        query += "  OR (    TABLE_SCHEMA  LIKE '#{column[:database]}'
                          AND TABLE_NAME    LIKE '#{column[:table]}'
                          AND COLUMN_NAME   LIKE '#{column[:name]}'"

        if column.has_key?(:type)
          query += "    AND COLUMN_TYPE   LIKE '#{column[:type]}'"
        end

        if column.has_key?(:null)
          query += "    AND IS_NULLABLE   LIKE '#{column[:null].to_s.upcase}'"
        end

        if column.has_key?(:default_value)
          if column[:default_value].to_s.downcase == 'null'
            query += "    AND COLUMN_DEFAULT IS NULL"
          else
            query += "    AND COLUMN_DEFAULT LIKE '#{column[:default_value]}'"
          end
        end

        if column.has_key?(:extra)
          query += "    AND EXTRA         LIKE '#{column[:extra]}'"
        end

        query += "  )"
      end

      query += "  , TRUE, FALSE) as column_exists
                  FROM INFORMATION_SCHEMA.COLUMNS
                  WHERE 1 = 0"

      @columns.each do |column|
        query += "  OR (    TABLE_SCHEMA  LIKE '#{column[:database]}'
                          AND TABLE_NAME    LIKE '#{column[:table]}'
                          AND COLUMN_NAME   LIKE '#{column[:name]}'
                      )"
      end

      result_columns = mysql_cli_query query


      # Compare Array of returned results with Array of columns we demand to be
      # present, and fill @columns_new and @columns_modify Arrays to be used by
      # create

      @columns_new = @columns.dup

      @columns.each do |column|
        result_columns.each do |result_column|
          if column[:name] == result_column[:col] && column[:table] == result_column[:tb] && column[:database] == result_column[:db]
            @columns_new.delete(column)
            if result_column[:column_exists] == 0.to_s
              # When doing CHANGE COLUMN, we HAVE to specify type. If it is not
              # specified by the manifest, we should use the one that is already
              # present.
              unless column.has_key?(:type)
                column[:original_type] = result_column[:type]
              end
              @columns_modify.push(column)
            end
          end
        end
      end

      if @columns_new.length > 0 || @columns_modify.length > 0
        return false
      else
        return true
      end

    end
    private :columns_exist?


    #
    # Verifies if provided indexes exist and have the same properties as
    # expected by the manifest
    #
    # Populates @indexes_new and @indexes_modify
    #
    # Returns true if all databases exist and have provided parameters
    #
    def indexes_exist?

      @indexes_new = Array.new
      @indexes_modify = Array.new

      query = " SELECT TABLE_SCHEMA as db, TABLE_NAME as tb, COLUMN_NAME as col, INDEX_NAME as name, SEQ_IN_INDEX as seq,
                          IF (1 = 0"

      @indexes.each do |index|

        query += "  OR (    TABLE_SCHEMA  LIKE '#{index[:database]}'
                          AND TABLE_NAME  LIKE '#{index[:table]}'
                          AND ( 1 = 0"

        index[:columns].each do |index_column|
          query += "        OR COLUMN_NAME LIKE '#{index_column}' "
        end

        query += "        )"

        if index.has_key?(:name)
          query += "    AND INDEX_NAME LIKE '#{index[:name]}'"
        end

        if index.has_key?(:type)
          if (index[:type] == :primary)
            query += "  AND INDEX_NAME = 'PRIMARY'"
          elsif (index[:type] == :unique)
            query += "  AND INDEX_NAME != 'PRIMARY' AND NON_UNIQUE = 0"
          elsif (index[:type] == :index)
            query += "  AND INDEX_NAME != 'PRIMARY' AND NON_UNIQUE = 1"
          end
        end

        query += "  )"
      end

      query += "  , TRUE, FALSE) as index_exists
                  FROM INFORMATION_SCHEMA.STATISTICS
                  WHERE 1 = 0"

      @indexes.each do |index|
        query += "  OR (    TABLE_SCHEMA  LIKE '#{index[:database]}'
                          AND TABLE_NAME    LIKE '#{index[:table]}'
                          AND ( 1 = 0"

        index[:columns].each do |index_column|
          query += "        OR COLUMN_NAME LIKE '#{index_column}' "
        end

        query += "        )
                    ) OR (TABLE_SCHEMA LIKE '#{index[:database]}' AND TABLE_NAME LIKE '#{index[:table]}' AND INDEX_NAME LIKE 'PRIMARY')"
      end

      result_indexes = mysql_cli_query query


      # Compare Array of returned results with Array of indexes we demand to be
      # present, and fill @indexes_new and @indexes_modify Arrays to be used
      # by create

      @indexes_new = @indexes.dup

      @indexes.each do |index|

        # Indexes can be applied to either one or multiple columns. When index is
        # applied to multiple columns we modify the existent index only if it is
        # applied to ALL specified columns, but is not of the right type or name.
        # We create a new index if the existent index is NOT applied to ALL specified
        # columns.
        # Since indexes can not be modified in MySQL, only removed and re-added, we
        # store old index name and possible index with the same name, so they are
        # removed before specified index it added.

        # Hash of existent index names, so we can check out if name of the index we
        # will later add already exists.
        existent_indexes = Hash.new

        result_indexes.each do |result_index|
          existent_indexes["#{result_index[:db]}.#{result_index[:tb]}.#{result_index[:name]}"] = true
        end

        new_count = index[:columns].length
        modify = false
        # Current name of the index we will modify
        old_name = nil

        index[:columns].each do |index_column|
          result_indexes.each do |result_index|
            if index_column == result_index[:col] && index[:table] == result_index[:tb] && index[:database] == result_index[:db]
              new_count -= 1
              if result_index[:index_exists] == 0.to_s
                modify = true
                old_name = result_index[:name]
              end
            end
          end
        end

        if new_count <= 0
          @indexes_new.delete(index)
        end
        if modify == true
          index[:old_name] = old_name
          if existent_indexes.has_key?("#{index[:database]}.#{index[:table]}.#{index[:assigned_name]}")
            index[:name_exists] = true
          end
          @indexes_modify.push(index)
        end

      end

      if @indexes_new.length > 0 || @indexes_modify.length > 0
        return false
      else
        return true
      end

    end
    private :indexes_exist?



    #
    # Verifies if provided users exist and have the same global permissions as
    # expected by the manifest
    #
    # Populates @users_global_new and @users_global_modify
    #
    # Returns true if all users with global permissions exist and have provided
    # parameters
    #
    def users_global_exist?

      @users_global_new = Array.new
      @users_global_modify = Array.new

      query = "   SELECT  *, IF (1 = 0"

      @users_global.each do |user|
        query += "  OR (  Host          LIKE '#{user[:escaped_host]}'
                          AND User      LIKE '#{user[:name]}'"

        if user.has_key?(:password)
          query += "      AND Password  LIKE PASSWORD('#{user[:password]}')"
        elsif user.has_key?(:password_encrypted)
          query += "      AND Password  LIKE '#{user[:password_encrypted]}'"
        end

        query += "  )"
      end

      query += "  , TRUE, FALSE) as password_match

                  FROM    mysql.user
                  WHERE   1 = 0"

      @users_global.each do |user|

        query += "  OR (  Host          LIKE '#{user[:escaped_host]}'
                          AND User      LIKE '#{user[:name]}')"

      end

      result_users = mysql_cli_query query


      # Compare Array of returned results with Array of privileges we demand to be
      # present, and fill @users_global_new and @users_global_modify Arrays to
      # be used by create

      @users_global_new = @users_global.dup

      @users_global.each do |user|
        result_users.each do |result_user|

          if user[:name] == result_user[:User] && user[:host].to_s == result_user[:Host]
            @users_global_new.delete(user)
            if result_user[:password_match] == 0.to_s
              @users_global_modify.push(user)
            else
              all_privileges = true
              no_privileges = true
              grant = false
              must_modify = false
              result_user.each do |key, value|
                if (key.to_s[-5,5] == '_priv')
                  if value == 'N'
                    if key != :Grant_priv # ALL PRIVILEGES do not grant GRANT permission
                      all_privileges = false
                    end
                  elsif value == 'Y'
                    no_privileges = false
                  end

                  if key == :Grant_priv && value == 'Y'
                    grant = true
                  end

                  if user[:privilege_type].include?(PRIVILEGE_COLS.index(key.to_sym))
                    if value == 'N'
                      must_modify = true
                    end
                  else
                    if value == 'Y'
                      must_modify = true
                    end
                  end

                end
              end
              if user[:privilege_type][0] == :usage
                if no_privileges == false
                  @users_global_modify.push(user)
                end
              elsif user[:privilege_type].include? :"all privileges"
                if all_privileges == false
                  @users_global_modify.push(user)
                elsif user[:privilege_type].include? :"grant option"
                  if grant == false
                    @users_global_modify.push(user)
                  end
                else
                  if grant == true
                    @users_global_modify.push(user)
                  end
                end
              elsif must_modify == true
                @users_global_modify.push(user)
              end
            end
          end

        end
      end

      if @users_global_new.length > 0 || @users_global_modify.length > 0
        return false
      else
        return true
      end

    end
    private :users_global_exist?



    #
    # Creates users with global privileges that do not exist yet
    #
    def users_global_create

      @users_global_new.each do |user|

        @create_notice[:users_created] += "\n  #{user[:name]} (global #{user[:privilege_type].join(", ").upcase})"

        # GRANT OPTION privilege is set separately
        if user[:privilege_type].include? :"grant option"
          user = user.dup
          user[:privilege_type].delete :"grant option"
          grant = true
        end

        query = " GRANT #{user[:privilege_type].join(", ")} ON *.* TO '#{user[:name]}'@'#{user[:host]}'"

        if user.has_key?(:password)
          query += "  IDENTIFIED BY '#{user[:password]}'"
        elsif user.has_key?(:password_encrypted)
          query += "  IDENTIFIED BY PASSWORD '#{user[:password_encrypted]}'"
        end

        if grant == true
          query += "  WITH GRANT OPTION"
        end

        mysql_cli_query query

      end

    end
    private :users_global_create



    #
    # Modifies users with global privileges that do not exist yet
    #
    def users_global_modify

      @users_global_modify.each do |user|

        @create_notice[:users_modified] += "\n  #{user[:name]} (global #{user[:privilege_type].join(", ").upcase})"

        # GRANT OPTION privilege is set separately
        if user[:privilege_type].include? :"grant option"
          user = user.dup
          user[:privilege_type].delete :"grant option"
          grant = true
        end

        query = " REVOKE GRANT OPTION ON *.* FROM '#{user[:name]}'@'#{user[:host]}';
                  REVOKE ALL PRIVILEGES  ON *.* FROM '#{user[:name]}'@'#{user[:host]}';
                  GRANT #{user[:privilege_type].join(", ").upcase} ON *.* TO '#{user[:name]}'@'#{user[:host]}'"

        if user.has_key?(:password)
          query += "  IDENTIFIED BY '#{user[:password]}'"
        elsif user.has_key?(:password_encrypted)
          query += "  IDENTIFIED BY PASSWORD '#{user[:password_encrypted]}'"
        end

        if grant == true
          query += "  WITH GRANT OPTION"
        end

        mysql_cli_query query

      end

    end
    private :users_global_modify



    #
    # Verifies if provided users exist and have the same database permissions as
    # expected by the manifest
    #
    # Populates @users_database_new and @users_database_modify
    #
    # Returns true if all users with database permissions exist and have provided
    # parameters
    #
    def users_database_exist?

      @users_database_new = Array.new
      @users_database_modify = Array.new

      query = "   SELECT  *
                  FROM    mysql.db
                  WHERE   1 = 0"

      @users_database.each do |user|

        query += "  OR (  Host          LIKE '#{user[:escaped_host]}'
                          AND User      LIKE '#{user[:name]}'
                          AND Db        LIKE '#{user[:privilege_database]}')"

      end

      result_users = mysql_cli_query query

      # Compare Array of returned results with Array of privileges we demand to be
      # present, and fill @users_global_new and @users_global_modify Arrays to
      # be used by create

      @users_database_new = @users_database.dup

      @users_database.each do |user|

        result_users.each do |result_user|
          if user[:name] == result_user[:User] && user[:host].to_s == result_user[:Host] && user[:privilege_database].to_s == result_user[:Db]
            @users_database_new.delete(user)

            all_privileges = true
            no_privileges = true
            grant = false
            must_modify = false
            result_user.each do |key, value|
              if (key.to_s[-5,5] == '_priv')
                if value == 'N'
                  if key != :Grant_priv # ALL PRIVILEGES do not grant GRANT permission
                    all_privileges = false
                  end
                elsif value == 'Y'
                  no_privileges = false
                end

                if key == :Grant_priv && value == 'Y'
                  grant = true
                end

                if user[:privilege_type].include?(PRIVILEGE_COLS.index(key.to_sym))
                  if value == 'N'
                    must_modify = true
                  end
                else
                  if value == 'Y'
                    must_modify = true
                  end
                end

              end
            end
            if user[:privilege_type][0] == :usage
              if no_privileges == false
                @users_database_modify.push(user)
              end
            elsif user[:privilege_type].include? :"all privileges"
              if all_privileges == false
                @users_database_modify.push(user)
              elsif user[:privilege_type].include? :"grant option"
                if grant == false
                  @users_database_modify.push(user)
                end
              else
                if grant == true
                  @users_database_modify.push(user)
                end
              end
            elsif must_modify == true
              @users_database_modify.push(user)
            end

          end
        end
      end

      if @users_database_new.length > 0 || @users_database_modify.length > 0
        return false
      else
        return true
      end

    end
    private :users_database_exist?    
    
    

    #
    # Creates users with database privileges that do not exist yet
    #
    def users_database_create

      @users_database_new.each do |user|

        @create_notice[:users_created] += "\n  #{user[:name]} (database '#{user[:privilege_database]}' #{user[:privilege_type].join(", ").upcase})"

        # GRANT OPTION privilege is set separately
        if user[:privilege_type].include? :"grant option"
          user = user.dup
          user[:privilege_type].delete :"grant option"
          grant = true
        end

        query = " GRANT #{user[:privilege_type].join(", ")} ON `#{user[:privilege_database]}`.* TO '#{user[:name]}'@'#{user[:host]}'"

        if user.has_key?(:password)
          query += "  IDENTIFIED BY '#{user[:password]}'"
        elsif user.has_key?(:password_encrypted)
          query += "  IDENTIFIED BY PASSWORD '#{user[:password_encrypted]}'"
        end

        if grant == true
          query += "  WITH GRANT OPTION"
        end

        mysql_cli_query query

      end

    end
    private :users_database_create



    #
    # Modifies users with database privileges that do not exist yet
    #
    def users_database_modify

      @users_database_modify.each do |user|

        @create_notice[:users_modified] += "\n  #{user[:name]} (database '#{user[:privilege_database]}' #{user[:privilege_type].join(", ").upcase})"

        # GRANT OPTION privilege is set separately
        if user[:privilege_type].include? :"grant option"
          user = user.dup
          user[:privilege_type].delete :"grant option"
          grant = true
        end

        query = " REVOKE GRANT OPTION ON `#{user[:privilege_database]}`.* FROM '#{user[:name]}'@'#{user[:host]}';
                  REVOKE ALL PRIVILEGES  ON `#{user[:privilege_database]}`.* FROM '#{user[:name]}'@'#{user[:host]}';
                  GRANT #{user[:privilege_type].join(", ").upcase} ON `#{user[:privilege_database]}`.* TO '#{user[:name]}'@'#{user[:host]}'"

        if user.has_key?(:password)
          query += "  IDENTIFIED BY '#{user[:password]}'"
        elsif user.has_key?(:password_encrypted)
          query += "  IDENTIFIED BY PASSWORD '#{user[:password_encrypted]}'"
        end

        if grant == true
          query += "  WITH GRANT OPTION"
        end

        mysql_cli_query query

      end

    end
    private :users_database_modify



    #
    # Verifies if provided users exist and have the same table permissions as
    # expected by the manifest
    #
    # Populates @users_table_new and @users_table_modify
    #
    # Returns true if all users with table permissions exist and have provided
    # parameters
    #
    def users_table_exist?

      @users_table_new = Array.new
      @users_table_modify = Array.new

      query = "   SELECT  *
                  FROM    mysql.tables_priv
                  WHERE   1 = 0"

      @users_table.each do |user|

        query += "  OR (  Host          LIKE '#{user[:host]}'
                          AND User      LIKE '#{user[:name]}'
                          AND Db        LIKE '#{user[:privilege_database]}'
                          AND Table_name LIKE '#{user[:privilege_table]}')"

      end

      result_users = mysql_cli_query query

      # Compare Array of returned results with Array of privileges we demand to be
      # present, and fill @users_global_new and @users_global_modify Arrays to
      # be used by create

      @users_table_new = @users_table.dup

      @users_table.each do |user|

        result_users.each do |result_user|
          if user[:name] == result_user[:User] && user[:host].to_s == result_user[:Host] && user[:privilege_database].to_s == result_user[:Db] && user[:privilege_table].to_s == result_user[:Table_name]
            @users_table_new.delete(user)

            all_privileges_w_grant = show_privileges :table
            all_privileges = all_privileges_w_grant.dup
            all_privileges.delete(:"grant option")
            current_privileges = result_user[:Table_priv].split(/,\s+|,/)
            current_privileges.map! {|value| value.downcase.gsub(/grant option|grant/, "grant option").to_sym}

            if user[:privilege_type].include? :"all privileges"
              privileges = all_privileges.dup
              if user[:privilege_type].include? :"grant option"
                privileges.push :"grant option"
              end
            elsif user[:privilege_type].include? :usage
              privileges = Array.new
            else
              privileges = user[:privilege_type]
            end

            # Do both Arrays have exactly same elements (order doesn't matter)?
            unless current_privileges & privileges == current_privileges && privileges & current_privileges == privileges
              puts 'wtf'
              @users_table_modify.push(user)
            end

          end
        end
      end

      if @users_table_new.length > 0 || @users_table_modify.length > 0
        return false
      else
        return true
      end

    end
    private :users_table_exist?



    #
    # Creates users with table privileges that do not exist yet and add user
    # column privileges
    #
    def users_table_create

      @users_table_new.each do |user|

        @create_notice[:users_created] += "\n  #{user[:name]} (table '#{user[:privilege_database]}.#{user[:privilege_table]}' #{user[:privilege_type].join(", ").upcase})"

        # GRANT OPTION privilege is set separately
        if user[:privilege_type].include? :"grant option"
          user = user.dup
          user[:privilege_type].delete :"grant option"
          grant = true
        end

        query = " GRANT #{user[:privilege_type].join(", ").upcase}"

        # Column privileges
        #
        # If table privileges are set to ALL PRIVILEGES, there is no need to set
        # up column privileges as table privileges apply to all columns in a
        # given table.
        #unless user[:privilege_type].include? :"all privileges"
          if @users_column_new.kind_of?(Array) && @users_column_new.length > 0
            @users_column_new.each do |user_column|

              unless user_column[:privilege_database] == user[:privilege_database] && user_column[:privilege_table] == user[:privilege_table]
                next
              end

              if user[:privilege_type].length > 0
                query += ","
              end
              query += " #{user_column[:privilege_type].join(" (#{user_column[:privilege_column]}), ")} (#{user_column[:privilege_column]})"

            end
          end
        #end

        query += " ON `#{user[:privilege_database]}`.`#{user[:privilege_table]}` TO '#{user[:name]}'@'#{user[:host]}'"

        if user.has_key?(:password)
          query += "  IDENTIFIED BY '#{user[:password]}'"
        elsif user.has_key?(:password_encrypted)
          query += "  IDENTIFIED BY PASSWORD '#{user[:password_encrypted]}'"
        end

        if grant == true
          query += "  WITH GRANT OPTION"
        end

        mysql_cli_query query

      end

    end
    private :users_table_create



    #
    # Modifies users with table privileges that do not exist yet
    #
    def users_table_modify

      # Obviously we modify all table privileges in @users_table_modify, but we
      # also need to modify table privileges, which are not in
      # @users_table_modify Array, but their columns are in @users_column_new
      # and @users_column_modify Arrays.
      users_column_new_and_modify = @users_column_new.dup.concat @users_column_modify
      
      users_column_new_and_modify.each do |user_column|
        table_present = false
        @users_table_modify.each do |user_table|
          if user_column[:name] == user_table[:name] && user_column[:host] == user_table[:host] && user_column[:privilege_database] == user_table[:privilege_database] && user_column[:privilege_table] == user_table[:privilege_table]
            table_present = true
            break
          end
        end

        if table_present == false
          @users_table.each do |user_table|
            if user_column[:name] == user_table[:name] && user_column[:host] == user_table[:host] && user_column[:privilege_database] == user_table[:privilege_database] && user_column[:privilege_table] == user_table[:privilege_table]
              @users_table_modify.push(user_table.dup)
            end
          end
        end
      end


      @users_table_modify.each do |user|

        @create_notice[:users_modified] += "\n  #{user[:name]} (table '#{user[:privilege_database]}.#{user[:privilege_table]}' #{user[:privilege_type].join(", ").upcase})"

        # GRANT OPTION privilege is set separately
        if user[:privilege_type].include? :"grant option"
          user = user.dup
          user[:privilege_type].delete :"grant option"
          grant = true
        end

        query = " REVOKE GRANT OPTION ON `#{user[:privilege_database]}`.`#{user[:privilege_table]}` FROM '#{user[:name]}'@'#{user[:host]}';
                  REVOKE ALL PRIVILEGES ON `#{user[:privilege_database]}`.`#{user[:privilege_table]}` FROM '#{user[:name]}'@'#{user[:host]}';
                  GRANT #{user[:privilege_type].join(", ").upcase}"

        # Column privileges
        #
        # If table privileges are set to ALL PRIVILEGES, there is no need to set
        # up column privileges as table privileges apply to all columns in a
        # given table.
        #unless user[:privilege_type].include? :"all privileges"
          if @users_column_new.kind_of?(Array) && @users_column_new.length > 0
            @users_column_new.each do |user_column|

              unless user_column[:privilege_database] == user[:privilege_database] && user_column[:privilege_table] == user[:privilege_table]
                next
              end

              @create_notice[:users_created] += "\n  #{user_column[:name]} (column '#{user_column[:privilege_database]}.#{user_column[:privilege_table]}.#{user_column[:privilege_column]}' #{user_column[:privilege_type].join(", ").upcase})"

              if user[:privilege_type].length > 0
                query += ","
              end
              query += " #{user_column[:privilege_type].join(" (#{user_column[:privilege_column]}), ")} (#{user_column[:privilege_column]})"

            end
          end
          if @users_column_modify.kind_of?(Array) && @users_column_modify.length > 0
            @users_column_modify.each do |user_column|

              unless user_column[:privilege_database] == user[:privilege_database] && user_column[:privilege_table] == user[:privilege_table]
                next
              end

              @create_notice[:users_modified] += "\n  #{user_column[:name]} (column '#{user_column[:privilege_database]}.#{user_column[:privilege_table]}.#{user_column[:privilege_column]}' #{user_column[:privilege_type].join(", ").upcase})"

              query += ", #{user_column[:privilege_type].join(" (#{user_column[:privilege_column]}), ")} (#{user_column[:privilege_column]})"

            end
          end
        #end

        query += " ON `#{user[:privilege_database]}`.`#{user[:privilege_table]}` TO '#{user[:name]}'@'#{user[:host]}'"

        if user.has_key?(:password)
          query += "  IDENTIFIED BY '#{user[:password]}'"
        elsif user.has_key?(:password_encrypted)
          query += "  IDENTIFIED BY PASSWORD '#{user[:password_encrypted]}'"
        end

        if grant == true
          query += "  WITH GRANT OPTION"
        end

        mysql_cli_query query

      end

    end
    private :users_table_modify



    #
    # Verifies if provided users exist and have the same column permissions as
    # expected by the manifest
    #
    # Populates @users_column_new and @users_column_modify
    #
    # Returns true if all users with table permissions exist and have provided
    # parameters
    #
    def users_column_exist?

      @users_column_new = Array.new
      @users_column_modify = Array.new

      query = "   SELECT  *
                  FROM    mysql.columns_priv
                  WHERE   1 = 0"

      @users_column.each do |user|

        query += "  OR (  Host          LIKE '#{user[:host]}'
                          AND User      LIKE '#{user[:name]}'
                          AND Db        LIKE '#{user[:privilege_database]}'
                          AND Table_name LIKE '#{user[:privilege_table]}'
                          AND Column_name LIKE '#{user[:privilege_column]}')"

      end

      result_users = mysql_cli_query query

      # Compare Array of returned results with Array of privileges we demand to
      # be present, and fill @users_global_new and @users_global_modify Arrays
      # to be used by create.
      @users_column_new = @users_column.dup

      @users_column.each do |user|

        result_users.each do |result_user|
          if user[:name] == result_user[:User] && user[:host].to_s == result_user[:Host] && user[:privilege_database].to_s == result_user[:Db] && user[:privilege_table].to_s == result_user[:Table_name] && user[:privilege_column].to_s == result_user[:Column_name]
            @users_column_new.delete(user)

            all_privileges = show_privileges :column

            current_privileges = result_user[:Column_priv].split(/,\s+|,/)
            current_privileges.map! {|value| value.downcase.to_sym}

            if user[:privilege_type].include? :"all privileges"
              privileges = all_privileges.dup
            elsif user[:privilege_type].include? :usage
              privileges = Array.new
            else
              privileges = user[:privilege_type]
            end

            # Do both Arrays have exactly same elements (order doesn't matter)?
            unless current_privileges & privileges == current_privileges && privileges & current_privileges == privileges
              @users_column_modify.push(user)
            end

          end
        end
      end

      if @users_column_new.length > 0 || @users_column_modify.length > 0
        return false
      else
        return true
      end

    end
    private :users_column_exist?



    #
    # Verifies if provided users exist and have the same procedure permissions
    # as expected by the manifest
    #
    # Populates @users_procedure_new and @users_procedure_modify
    #
    # Returns true if all users with procedure permissions exist and have
    # provided parameters
    #
    def users_procedure_exist?

      @users_procedure_new = Array.new
      @users_procedure_modify = Array.new

      query = "   SELECT  *
                  FROM    mysql.procs_priv
                  WHERE   1 = 0"

      @users_procedure.each do |user|

        query += "  OR (  Host          LIKE '#{user[:host]}'
                          AND User      LIKE '#{user[:name]}'
                          AND Db        LIKE '#{user[:privilege_database]}'
                          AND Routine_name LIKE '#{user[:privilege_procedure]}')"

      end

      result_users = mysql_cli_query query

      # Compare Array of returned results with Array of privileges we demand to
      # be present, and fill @users_procedure_new and @users_procedure_modify
      # Arrays to be used by create
      @users_procedure_new = @users_procedure.dup

      @users_procedure.each do |user|

        result_users.each do |result_user|
          if user[:name] == result_user[:User] && user[:host].to_s == result_user[:Host] && user[:privilege_database].to_s == result_user[:Db] && user[:privilege_procedure].to_s == result_user[:Routine_name]
            @users_procedure_new.delete(user)

            all_privileges_w_grant = show_privileges :procedure
            all_privileges = all_privileges_w_grant.dup
            all_privileges.delete(:"grant option")

            current_privileges = result_user[:Proc_priv].split(/,\s+|,/)
            current_privileges.map! {|value| value.downcase.gsub(/grant option|grant/, "grant option").to_sym}

            if user[:privilege_type].include? :"all privileges"
              privileges = all_privileges.dup
              if user[:privilege_type].include? :"grant option"
                privileges.push :"grant option"
              end
            elsif user[:privilege_type].include? :usage
              privileges = Array.new
            else
              privileges = user[:privilege_type]
            end

            # Do both Arrays have exactly same elements (order doesn't matter)?
            unless current_privileges & privileges == current_privileges && privileges & current_privileges == privileges
              @users_procedure_modify.push(user)
            end

          end
        end
      end

      if @users_procedure_new.length > 0 || @users_procedure_modify.length > 0
        return false
      else
        return true
      end

    end
    private :users_procedure_exist?



    #
    # Creates users with procedure privileges that do not exist yet
    #
    def users_procedure_create

      @users_procedure_new.each do |user|

        @create_notice[:users_created] += "\n  #{user[:name]} (procedure '#{user[:privilege_database]}.#{user[:privilege_procedure]}' #{user[:privilege_type].join(", ").upcase})"

        # GRANT OPTION privilege is set separately
        if user[:privilege_type].include? :"grant option"
          user = user.dup
          user[:privilege_type].delete :"grant option"
          grant = true
        end

        query = " GRANT #{user[:privilege_type].join(", ").upcase} ON PROCEDURE `#{user[:privilege_database]}`.`#{user[:privilege_procedure]}` TO '#{user[:name]}'@'#{user[:host]}'"

        if user.has_key?(:password)
          query += "  IDENTIFIED BY '#{user[:password]}'"
        elsif user.has_key?(:password_encrypted)
          query += "  IDENTIFIED BY PASSWORD '#{user[:password_encrypted]}'"
        end

        if grant == true
          query += "  WITH GRANT OPTION"
        end

        mysql_cli_query query

      end

    end
    private :users_procedure_create



    #
    # Modifies users with procedure privileges that do not exist yet
    #
    def users_procedure_modify

      @users_procedure_modify.each do |user|

        @create_notice[:users_modified] += "\n  #{user[:name]} (procedure '#{user[:privilege_database]}.#{user[:privilege_procedure]}' #{user[:privilege_type].join(", ").upcase})"

        # GRANT OPTION privilege is set separately
        if user[:privilege_type].include? :"grant option"
          user = user.dup
          user[:privilege_type].delete :"grant option"
          grant = true
        end

        query = " REVOKE GRANT OPTION ON PROCEDURE `#{user[:privilege_database]}`.`#{user[:privilege_procedure]}` FROM '#{user[:name]}'@'#{user[:host]}';
                  REVOKE ALL PRIVILEGES ON PROCEDURE `#{user[:privilege_database]}`.`#{user[:privilege_procedure]}` FROM '#{user[:name]}'@'#{user[:host]}';
                  GRANT #{user[:privilege_type].join(", ").upcase} ON PROCEDURE `#{user[:privilege_database]}`.`#{user[:privilege_procedure]}` TO '#{user[:name]}'@'#{user[:host]}'"

        if user.has_key?(:password)
          query += "  IDENTIFIED BY '#{user[:password]}'"
        elsif user.has_key?(:password_encrypted)
          query += "  IDENTIFIED BY PASSWORD '#{user[:password_encrypted]}'"
        end

        if grant == true
          query += "  WITH GRANT OPTION"
        end

        mysql_cli_query query

      end

    end
    private :users_procedure_modify

  end
end