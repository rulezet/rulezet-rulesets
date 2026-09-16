rule PortRacer {
   meta:
      description = "Auto-generated rule on file PortRacer.exe"
      author = "yarGen Yara Rule Generator by Florian Roth"
      hash = "2834a872a0a8da5b1be5db65dfdef388"
      id = "54717938-2f4c-5442-b0ad-40b9acd1101a"
   strings:
      $s0 = "Auto Scroll BOTH Text Boxes"
      $s4 = "Start/Stop Portscanning"
      $s6 = "Auto Save LogFile by pressing STOP"
   condition:
      all of them
}