rule APT_CryWiper_Dec22_RID2D59 : APT DEMO T1543_003 {
   meta:
      description = "Detects CryWiper malware samples"
      author = "Florian Roth"
      reference = "https://securelist-ru.translate.goog/novyj-troyanec-crywiper/106114/?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en"
      date = "2022-12-05 10:28:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, T1543_003"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Software\\Sysinternals\\BrowserUpdate" 
      $sx1 = "taskkill.exe /f /im MSExchange*" 
      $s1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server" ascii
      $s2 = "fDenyTSConnections" ascii
   condition: 
      1 of ( $x* ) or all of ( $s* )
}