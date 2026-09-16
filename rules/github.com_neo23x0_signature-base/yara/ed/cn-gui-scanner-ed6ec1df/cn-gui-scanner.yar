rule CN_GUI_Scanner {
   meta:
      description = "Detects an unknown GUI scanner tool - CN background"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      hash = "3c67bbb1911cdaef5e675c56145e1112"
      score = 65
      date = "04.10.2014"
      id = "ca88d4d3-5d18-5856-874f-e50deceef54f"
   strings:
      $s1 = "good.txt" fullword ascii
      $s2 = "IP.txt" fullword ascii
      $s3 = "xiaoyuer" fullword ascii
      $s0w = "ssh(" wide
      $s1w = ").exe" fullword wide
   condition:
      all of them
}