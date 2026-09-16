rule HKTL_HYTop2006_rar_Folder_2006X_RID311D : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2006X.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 13:08:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<input name=\"password\" type=\"password\" id=\"password\"" 
      $s6 = "name=\"theAction\" type=\"text\" id=\"theAction\"" 
   condition: 
      all of them
}