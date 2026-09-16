rule LOG_TeamViewer_Connect_Chinese_Keyboard_Layout_RID38FF : CHINA DEMO LOG T1072 T1219 {
   meta:
      description = "Detects a suspicious TeamViewer log entry stating that the remote systems had a Chinese keyboard layout"
      author = "Florian Roth"
      reference = "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs"
      date = "2019-10-12 18:45:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2020-12-16"
      tags = "CHINA, DEMO, LOG, T1072, T1219"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Changing keyboard layout to: 0804" ascii
      $x2 = "Changing keyboard layout to: 042a" 
      $fp1 = "Changing keyboard layout to: 08040804" ascii
      $fp2 = "Changing keyboard layout to: 042a042a" ascii
   condition: 
      ( #x1 + #x2 ) > ( #fp1 + #fp2 )
}