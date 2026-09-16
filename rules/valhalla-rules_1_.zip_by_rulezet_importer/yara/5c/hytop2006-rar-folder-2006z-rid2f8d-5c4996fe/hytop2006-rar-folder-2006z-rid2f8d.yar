rule HYTop2006_rar_Folder_2006Z_RID2F8D : DEMO T1505_003 T1543_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file 2006Z.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 12:02:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, T1543_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth" 
      $s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x" 
   condition: 
      all of them
}