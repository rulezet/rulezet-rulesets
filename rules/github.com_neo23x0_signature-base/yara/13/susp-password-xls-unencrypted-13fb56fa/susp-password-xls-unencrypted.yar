rule SUSP_Password_XLS_Unencrypted {
   meta:
      description = "Detects files named e.g. password.xls, which might contain unportected clear text passwords"
      author = "Arnim Rupp (https://github.com/ruppde)"
      reference = "Internal Research"
      date = "2023-10-04"
      score = 60
      id = "41096ef1-dd02-5956-9053-3d7fb1a5092c"
   condition:
            (
         filename istartswith "passwor" or        
         filename istartswith "contrase" or       
         filename istartswith "mot de pass" or   
         filename istartswith "mot_de_pass" or   
         filename istartswith "motdepass" or     
         filename istartswith "wachtwoord"        
      )
      and (
                    (
              filename iendswith ".xls"
              and uint32be(0) == 0xd0cf11e0           )
          or
          (
              filename iendswith ".xlsx"
              and uint32be(0) == 0x504b0304           )
      )
}