rule Empire_Out_Minidump {
   meta:
      description = "Detects Empire component - file Out-Minidump.ps1"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05"
      hash1 = "7803ae7ba5d4e7d38e73745b3f321c2ca714f3141699d984322fa92e0ff037a1"
      id = "8c53d2ab-afc5-5d7b-97e1-496425b9664f"
   strings:
      $s1 = "$Result = $MiniDumpWriteDump.Invoke($null, @($ProcessHandle," fullword ascii
      $s2 = "$ProcessFileName = \"$($ProcessName)_$($ProcessId).dmp\"" fullword ascii
   condition:
      ( uint16(0) == 0x7566 and filesize < 10KB and 1 of them ) or all of them
}