rule Empire_Invoke_PowerDump {
   meta:
      description = "Detects Empire component - file Invoke-PowerDump.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "095c5cf5c0c8a9f9b1083302e2ba1d4e112a410e186670f9b089081113f5e0e1"
      id = "d1082a4e-d458-57fb-b332-7c775c8ef2dd"
   strings:
      $x16 = "$enc = Get-PostHashdumpScript" fullword ascii
      $x19 = "$lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword;" fullword ascii
      $x20 = "$rc4_key = $md5.ComputeHash($hbootkey[0..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr);" fullword ascii
   condition:
      ( uint16(0) == 0x2023 and filesize < 60KB and 1 of them ) or all of them
}