rule HKTL_HYTop2006_rar_Folder_2006X2_RID314F : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2006X2.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 13:17:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s2 = "Powered By " 
      $s3 = " \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this." 
   condition: 
      all of them
}