rule Regin_Sample_Set_2_RID2DE3 : APT DEMO T1543_003 regin {
   meta:
      description = "Semiautomatically generated YARA rule - file SHF-000052 and ndisips.sys"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-25 10:51:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      hash1 = "8487a961c8244004c9276979bb4b0c14392fc3b8"
      hash2 = "bcf3461d67b39a427c83f9e39b9833cfec977c61"
      tags = "APT, DEMO, T1543_003, regin"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "HAL.dll" fullword ascii
      $s1 = "IoGetDeviceObjectPointer" fullword ascii
      $s2 = "MaximumPortsServiced" fullword wide
      $s3 = "KeGetCurrentIrql" fullword ascii
      $s4 = "ntkrnlpa.exe" fullword ascii
      $s5 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
      $s6 = "ConnectMultiplePorts" fullword wide
      $s7 = "\\SYSTEMROOT" wide
      $s8 = "IoWriteErrorLogEntry" fullword ascii
      $s9 = "KeQueryPerformanceCounter" fullword ascii
      $s10 = "KeServiceDescriptorTable" fullword ascii
      $s11 = "KeRemoveEntryDeviceQueue" fullword ascii
      $s12 = "SeSinglePrivilegeCheck" fullword ascii
      $s13 = "KeInitializeEvent" fullword ascii
      $s14 = "IoBuildDeviceIoControlRequest" fullword ascii
      $s15 = "KeRemoveDeviceQueue" fullword ascii
      $s16 = "IofCompleteRequest" fullword ascii
      $s17 = "KeInitializeSpinLock" fullword ascii
      $s18 = "MmIsNonPagedSystemAddressValid" fullword ascii
      $s19 = "IoCreateDevice" fullword ascii
      $s20 = "KefReleaseSpinLockFromDpcLevel" fullword ascii
   condition: 
      filesize < 40KB and filesize > 30KB and all of them
}