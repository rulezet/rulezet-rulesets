rule ZXshell2_0_rar_Folder_ZXshell_RID3224 : DEMO T1505_003 WEBSHELL zxshell {
   meta:
      description = "Webshells Auto-generated - file ZXshell.exe"
      author = "Florian Roth"
      reference = "-"
      date = "2014-04-06 13:52:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, T1505_003, WEBSHELL, zxshell"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "WPreviewPagesn" 
      $s1 = "DA!OLUTELY N" 
   condition: 
      all of them
}