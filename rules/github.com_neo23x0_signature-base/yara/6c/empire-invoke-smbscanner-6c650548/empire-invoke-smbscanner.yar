rule Empire_Invoke_SmbScanner {
   meta:
      description = "Detects Empire component - file Invoke-SmbScanner.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "9a705f30766279d1e91273cfb1ce7156699177a109908e9a986cc2d38a7ab1dd"
      id = "63cd048b-04fd-5b4f-9d4d-3a001c31b4df"
   strings:
      $s1 = "$up = Test-Connection -count 1 -Quiet -ComputerName $Computer " fullword ascii
      $s2 = "$out | add-member Noteproperty 'Password' $Password" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}