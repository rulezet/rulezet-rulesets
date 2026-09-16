rule HKTL_root_040_zip_Folder_deploy_RID32B3 : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file deploy.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:16:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s5 = "halon synscan 127.0.0.1 1-65536" 
      $s8 = "Obviously you replace the ip address with that of the target." 
   condition: 
      all of them
}