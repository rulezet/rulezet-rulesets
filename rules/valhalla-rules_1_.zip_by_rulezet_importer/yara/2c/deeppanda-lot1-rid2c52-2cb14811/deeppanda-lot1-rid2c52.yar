rule DeepPanda_lot1_RID2C52 : APT CHINA DEMO G0009 T1003 {
   meta:
      description = "Hack Deep Panda - FBI Liaison Alert System # A-000049-MW - lot1.tmp-pwdump"
      author = "Florian Roth"
      reference = "http://krebsonsecurity.com/wp-content/uploads/2015/02/FBI-Flash-Warning-Deep-Panda.pdf"
      date = "2015-02-08 09:44:11"
      score = 80
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, CHINA, DEMO, G0009, T1003"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Unable to open target process: %d, pid %d" fullword ascii
      $s1 = "Couldn't delete target executable from remote machine: %d" fullword ascii
      $s2 = "Target: Failed to load SAM functions." fullword ascii
      $s5 = "Error writing the test file %s, skipping this share" fullword ascii
      $s6 = "Failed to create service (%s/%s), error %d" fullword ascii
      $s8 = "Service start failed: %d (%s/%s)" fullword ascii
      $s12 = "PwDump.exe" fullword ascii
      $s13 = "GetAvailableWriteableShare returned an error of %ld" fullword ascii
      $s14 = ":\\\\.\\pipe\\%s" fullword ascii
      $s15 = "Couldn't copy %s to destination %s. (Error %d)" fullword ascii
      $s16 = "dump logon session" fullword ascii
      $s17 = "Timed out waiting to get our pipe back" fullword ascii
      $s19 = "SetNamedPipeHandleState failed, error %d" fullword ascii
      $s20 = "%s\\%s.exe" fullword ascii
   condition: 
      10 of them
}