rule DarkComet_Keylogger_File {
   meta:
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      description = "Looks like a keylogger file created by DarkComet Malware"
      date = "25.07.14"
      score = 50
      id = "65058450-3ae3-5b85-bcc5-8bc1fab14614"
   strings:
      $entry = /\n:: [A-Z]/
      $timestamp = /\([0-9]?[0-9]:[0-9][0-9]:[0-9][0-9] [AP]M\)/
   condition:
      uint16(0) == 0x3A3A and #entry > 10 and #timestamp > 10
}