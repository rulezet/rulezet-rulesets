rule SAM_Hive_Backup {
   meta:
      description = "Detects a SAM hive backup file - SAM is the Security Account Manager - contains password hashes"
      author = "Florian Roth"
      reference = "https://www.ired.team/offensive-security/credential-access-and-credential-dumping/dumping-hashes-from-sam-registry"
      score = 60
      nodeepdive = 1
      date = "2015-03-31"
      modified = "2023-12-12"
      id = "31fb6c0c-966d-5002-bf8c-4129964c81ff"
   strings:
      $s1 = "\\SystemRoot\\System32\\Config\\SAM" wide
   condition:
      uint32(0) == 0x66676572 and $s1 in (0..200)
      and not filepath contains "\\System32\\Config"
      and not filepath contains "\\System32\\config"
      and not filepath contains "System Volume Information"
      and not filepath contains "\\config\\RegBack"
}