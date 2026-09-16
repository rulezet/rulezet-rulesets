rule Ncrack {
   meta:
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      description = "This signature detects the Ncrack brute force tool"
      date = "01.07.2014"
      score = 60
      id = "c1c56ee9-7f76-5440-b0e0-86e372c53340"
   strings:
      $s1 = "NcrackOutputTable only supports adding up to 4096 to a cell via"
   condition:
      1 of them
}