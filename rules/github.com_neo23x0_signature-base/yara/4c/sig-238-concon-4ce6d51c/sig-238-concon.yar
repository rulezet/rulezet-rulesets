rule sig_238_concon {
   meta:
      description = "Disclosed hacktool set (old stuff) - file concon.com"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      date = "23.11.14"
      score = 60
      hash = "816b69eae66ba2dfe08a37fff077e79d02b95cc1"
      id = "ca7862cc-1053-5fce-a569-6ecc069314df"
   strings:
      $s0 = "Usage: concon \\\\ip\\sharename\\con\\con" fullword ascii
   condition:
      all of them
}