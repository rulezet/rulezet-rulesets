rule mimikatz_lsass_mdmp
{
   meta:
      description      = "LSASS minidump file for mimikatz"
      author         = "Benjamin DELPY (gentilkiwi)"
      id = "3d850dbe-1342-55ac-b0f7-91343d88f147"
   strings:
      $lsass         = "System32\\lsass.exe"   wide nocase
   condition:
      (uint32(0) == 0x504d444d) and $lsass and filesize > 50000KB and not filename matches /WER/
}