rule SQLMap {
   meta:
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      description = "This signature detects the SQLMap SQL injection tool"
      date = "01.07.2014"
      score = 60
      id = "55a72fe6-f82d-5d55-842f-5d7e1cfcc9fa"
   strings:
      $s1 = "except SqlmapBaseException, ex:"
   condition:
      1 of them
}