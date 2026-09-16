rule Chinese_Hacktool_1014 {
   meta:
      description = "Detects a chinese hacktool with unknown use"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      score = 60
      date = "10.10.2014"
      hash = "98c07a62f7f0842bcdbf941170f34990"
      id = "e5db5f58-a1fd-51e0-9037-337fcca71f11"
   strings:
      $s0 = "IEXT2_IDC_HORZLINEMOVECURSOR" fullword wide
      $s1 = "msctls_progress32" fullword wide
      $s2 = "Reply-To: %s" fullword ascii
      $s3 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" fullword ascii
      $s4 = "html htm htx asp" fullword ascii
   condition:
      all of them
}