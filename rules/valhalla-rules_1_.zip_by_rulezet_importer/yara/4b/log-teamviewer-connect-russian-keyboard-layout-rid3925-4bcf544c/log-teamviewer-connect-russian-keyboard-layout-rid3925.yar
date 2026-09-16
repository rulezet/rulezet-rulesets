rule LOG_TeamViewer_Connect_Russian_Keyboard_Layout_RID3925 : DEMO LOG T1072 T1219 {
   meta:
      description = "Detects a suspicious TeamViewer log entry stating that the remote systems had a Russian keyboard layout"
      author = "Florian Roth"
      reference = "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs"
      date = "2019-10-12 18:51:21"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-07"
      tags = "DEMO, LOG, T1072, T1219"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Changing keyboard layout to: 0419" ascii
      $fp1 = "Changing keyboard layout to: 04190419" ascii
   condition: 
      #x1 > #fp1
}