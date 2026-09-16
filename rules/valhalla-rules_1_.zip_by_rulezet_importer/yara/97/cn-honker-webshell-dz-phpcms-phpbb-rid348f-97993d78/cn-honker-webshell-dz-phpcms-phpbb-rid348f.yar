rule CN_Honker_Webshell_dz_phpcms_phpbb_RID348F : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file dz_phpcms_phpbb.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 15:35:41"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "if($pwd == md5(md5($password).$salt))" fullword ascii
      $s2 = "function test_1($password)" fullword ascii
      $s3 = ":\".$pwd.\"\\n---------------------------------\\n\";exit;" fullword ascii
      $s4 = ":user=\".$user.\"\\n\";echo \"pwd=\".$pwd.\"\\n\";echo \"salt=\".$salt.\"\\n\";" fullword ascii
   condition: 
      filesize < 22KB and all of them
}