rule SUSP_Password_XLS_Encrypted {
   meta:
      description = "Detects files named e.g. password.xlsx, which might contain clear text passwords, but are password protected from MS Office"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "Internal Research"
      date = "2023-10-04"
      score = 50
      id = "d3334923-3396-524d-9111-8ccb754ab99e"
   condition:
            (
         filename istartswith "passwor" or        
         filename istartswith "contrase" or       
         filename istartswith "mot de pass" or   
         filename istartswith "mot_de_pass" or   
         filename istartswith "motdepass" or     
         filename istartswith "wachtwoord"        
      )
      and filename iendswith ".xlsx"
      and uint32be(0) == 0xd0cf11e0 }