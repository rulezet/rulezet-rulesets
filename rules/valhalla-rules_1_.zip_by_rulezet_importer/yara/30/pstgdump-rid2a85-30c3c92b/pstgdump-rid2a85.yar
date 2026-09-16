rule pstgdump_RID2A85 : DEMO EXE FILE HKTL {
   meta:
      description = "Detects a tool used by APT groups - file pstgdump_RID2A85.exe"
      author = "Florian Roth"
      reference = "https://community.broadcom.com/home"
      date = "2016-09-08 06:33:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2024-07-19"
      hash1 = "65d48a2f868ff5757c10ed796e03621961954c523c71eac1c5e044862893a106"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "\\Release\\pstgdump_RID2A85.pdb" ascii
      $x2 = "Failed to dump all protected storage items - see previous messages for details" fullword ascii
      $x3 = "ptsgdump [-h][-q][-u Username][-p Password]" fullword ascii
      $x4 = "Attempting to impersonate domain user '%s' in domain '%s'" fullword ascii
      $x5 = "Failed to impersonate user (ImpersonateLoggedOnUser failed): error %d" fullword ascii
      $x6 = "Unable to obtain handle to PStoreCreateInstance in pstorec.dll" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and 1 of ( $x* ) ) or ( 3 of them )
}