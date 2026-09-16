rule LOG_TeamViewer_Connect_Russian_Keyboard_Layout {
   meta:
      description = "Detects a suspicious TeamViewer log entry stating that the remote systems had a Russian keyboard layout"
      author = "Florian Roth (Nextron Systems)"
      date = "2019-10-12"
      modified = "2022-12-07"
      score = 60
      limit = "Logscan"
      reference = "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs"
      id = "360a1cca-2a64-5fd8-bcde-f49e1b17281e"
   strings:
      
      $x1 = "Changing keyboard layout to: 0419" ascii
      
      $fp1 = "Changing keyboard layout to: 04190419" ascii
   condition:
      #x1 > #fp1
}