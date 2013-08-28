require 'jamsi_mysql'

mysql = Jamsi::Mysql.new 'localhost', 'root', 'geslo'

manifest = {
    :users       => [
        { :name => 'testuser', :host => 'localhost', :password => 'geslo', :privileges => [
            { :scope => 'global', :type => 'SELECT, GRANT' },
            { :scope => 'database', :type => 'ALL,GRANT', :database => 'testdb' },
            { :scope => 'table', :type => 'SELECT, GRANT', :database => 'testdb', :table => 'test' },
            { :scope => 'column', :type => ['SELECT', 'UPDATE'], :database => 'testdb', :table => 'test', :column => 'krneki' },
            { :scope => 'procedure', :type => 'ALL, GRANT', :database => 'testdb', :procedure => 'laufej' }
        ] },
        { :name => 'testuser2', :password_encrypted => '*688A703BC41CD46010FB575704D602CBAB5A9916', :privileges => [
          { :scope => 'database', :type => 'SELECT, UPDATE', :database => 'testdb' },
          { :scope => 'column', :type => 'SELECT, INSERT', :database => 'testdb', :table => 'test', :column => 'krneki' },
        ]}
    ],
    :databases   => [
        { :name => 'testdb', :collation => 'latin1_swedish_ci' },
        { :name => 'testdb2', :character_set => 'utf8' }
    ],
    :tables      => [
        { :database => 'testdb', :name => 'test', :engine => 'InnoDB' },
        { :database => 'testdb', :name => 'testtable', :engine => 'MyISAM', :character_set => 'utf8' }
    ],
    :columns     => [
        { :database => 'testdb', :table => 'test', :name => 'id', :type => 'INT(11)', :null => 'NO', :index => 'primary', :extra => 'AUTO_INCREMENT' },
        { :database => 'testdb', :table => 'test', :name => 'name', :type => 'VARCHAR(64)', :null => 'NO', :default_value => 'no-name'},
        { :database => 'testdb', :table => 'test', :name => 'address', :type => 'VARCHAR(128)', :null => 'YES', :default_value => 'NULL'},
        { :database => 'testdb', :table => 'test', :name => 'krneki', :type => 'VARCHAR(64)'},
        { :database => 'testdb', :table => 'testtable', :name => 'krneki', :type => 'VARCHAR(64)'},
    ],
    :indexes     => [
        { :database => 'testdb', :table => 'test', :columns => 'name', :type => 'unique' },
        { :database => 'testdb', :table => 'test', :columns => ['address', 'krneki'] },
    ]
}

puts "exists?\n-----"
puts mysql.exists? manifest

puts "\ncreate\n-----"
mysql.create manifest