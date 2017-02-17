CONTENTS OF THIS FILE
---------------------
 * Configuration
 * Enjoy :D
---------------------

* Configuration

To run the program, there are 2 options:

/src contains the main codes
/out contains the the compiled classes and jar
/Client, /Client2, /Server, /Server2 contains the manifest required to run the jar files
users.txt and mykeystore.jks is required if running the program from Intellij


	1: Import project into Intellij to run
		*Changing the location of user.txt and mykeystore.jks in the root folder reuires change of directory in code
		*E.g private static final String USERS_FILE_NAME = "users.txt"; in UserAuthentication.java
		*Code that requires directory change if needed 
			-UserAuthentication.java
			-Server.java
			-SSLUtils.java

	2: There are pre-compiled jar files available to run at \ACG_Assignment\out\artifacts
		- To run the jar file using terminal, 
		- cd into \ACG_Assignment\out\artifact (there should be 4 folders, 1 user.txt, 1 mykeystore.jks)
		 	> java -jar [folder_name]/[file.jar] --> Server/Server.jar
	

	*The user.txt file used by the 2 methods are different



 * Enjoy :)

             ,----------------,              ,---------,
        ,-----------------------,          ,"        ,"|
      ,"                      ,"|        ,"        ,"  |
     +-----------------------+  |      ,"        ,"    |
     |  .-----------------.  |  |     +---------+      |
     |  |                 |  |  |     | -==----'|      |
     |  |  I LOVE ACG!    |  |  |     |         |      |
     |  |                 |  |  |/----|`---=    |      |
     |  |  C:\>_          |  |  |   ,/|==== ooo |      ;
     |  |                 |  |  |  // |(((( [33]|    ,"
     |  `-----------------'  |," .;'| |((((     |  ,"
     +-----------------------+  ;;  | |         |,"
        /_)______________(_/  //'   | +---------+
   ___________________________/___  `,
  /  oooooooooooooooo  .o.  oooo /,   \,"-----------
 / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
/_==__==========__==_ooo__ooo=_/'   /___________,"
                       