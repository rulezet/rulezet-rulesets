rule Regin_Sample_2_RID2C58 : APT DEMO T1543_003 regin {
   meta:
      description = "Semiautomatically generated YARA rule - file hiddenmod_hookdisk_and_kdbg_8949d000.bin"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-25 09:45:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, T1543_003, regin"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "\\SYSTEMROOT\\system32\\lsass.exe" wide
      $s1 = "atapi.sys" fullword wide
      $s2 = "disk.sys" fullword wide
      $s3 = "IoGetRelatedDeviceObject" fullword ascii
      $s4 = "HAL.dll" fullword ascii
      $s5 = "\\Registry\\Machine\\System\\CurrentControlSet\\Services" ascii
      $s6 = "PsGetCurrentProcessId" fullword ascii
      $s7 = "KeGetCurrentIrql" fullword ascii
      $s8 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager" wide
      $s9 = "KeSetImportanceDpc" fullword ascii
      $s10 = "KeQueryPerformanceCounter" fullword ascii
      $s14 = "KeInitializeEvent" fullword ascii
      $s15 = "KeDelayExecutionThread" fullword ascii
      $s16 = "KeInitializeTimerEx" fullword ascii
      $s18 = "PsLookupProcessByProcessId" fullword ascii
      $s19 = "ExReleaseFastMutexUnsafe" fullword ascii
      $s20 = "ExAcquireFastMutexUnsafe" fullword ascii
   condition: 
      filesize < 40KB and filesize > 30KB and all of them
}