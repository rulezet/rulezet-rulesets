rule HKTL_ZXshell2_0_rar_Folder_zxrecv_RID338E : DEMO HKTL T1505_003 WEBSHELL {
   meta:
      description = "Webshells Auto-generated - file zxrecv.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-07 14:52:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, HKTL, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "RyFlushBuff" 
      $s1 = "teToWideChar^FiYP" 
      $s2 = "mdesc+8F D" 
      $s3 = "\\von76std" 
      $s4 = "5pur+virtul" 
      $s5 = "- Kablto io" 
      $s6 = "ac#f{lowi8a" 
   condition: 
      all of them
}