rule LOG_TeamViewer_Connect_Chinese_Keyboard_Layout {
   meta:
      description = "Detects a suspicious TeamViewer log entry stating that the remote systems had a Chinese keyboard layout"
      author = "Florian Roth (Nextron Systems)"
      date = "2019-10-12"
      modified = "2020-12-16"
      score = 60
      limit = "Logscan"
      reference = "https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/default-input-locales-for-windows-language-packs"
      id = "f901818b-5150-540f-b645-686c12784a38"
   strings:
      
      $x1 = "Changing keyboard layout to: 0804" ascii
      $x2 = "Changing keyboard layout to: 042a"
      
      $fp1 = "Changing keyboard layout to: 08040804" ascii
      $fp2 = "Changing keyboard layout to: 042a042a" ascii
   condition:
      ( #x1 + #x2 ) > ( #fp1 + #fp2 )
}