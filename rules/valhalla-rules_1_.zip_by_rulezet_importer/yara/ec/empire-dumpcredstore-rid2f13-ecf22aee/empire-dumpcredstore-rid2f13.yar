rule Empire_dumpCredStore_RID2F13 : DEMO SCRIPT T1059 T1059_001 {
   meta:
      description = "Detects Empire component - file dumpCredStore.ps1"
      author = "Florian Roth"
      reference = "https://github.com/adaptivethreat/Empire"
      date = "2016-11-05 11:41:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "c1e91a5f9cc23f3626326dab2dcdf4904e6f8a332e2bce8b9a0854b371c2b350"
      tags = "DEMO, SCRIPT, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "[DllImport(\"Advapi32.dll\", SetLastError = true, EntryPoint = \"CredReadW\"" ascii
      $s12 = "[String] $Msg = \"Failed to enumerate credentials store for user '$Env:UserName'\"" fullword ascii
      $s15 = "Rtn = CredRead(\"Target\", CRED_TYPE.GENERIC, out Cred);" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x233c and filesize < 40KB and 1 of them ) or all of them
}