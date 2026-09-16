rule Regin_Sample_3_RID2C59 : APT DEMO FILE T1543_003 regin {
   meta:
      description = "Detects Regin Backdoor sample fe1419e9dde6d479bd7cda27edd39fafdab2668d498931931a2769b370727129"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-27 09:45:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, FILE, T1543_003, regin"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Service Pack x" fullword wide
      $s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" wide
      $s2 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\HotFix" wide
      $s3 = "mntoskrnl.exe" fullword wide
      $s4 = "\\REGISTRY\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Memory Management" wide
      $s5 = "Memory location: 0x%p, size 0x%08x" wide fullword
      $s6 = "Service Pack" fullword wide
      $s7 = ".sys" fullword wide
      $s8 = ".dll" fullword wide
      $s10 = "\\REGISTRY\\Machine\\Software\\Microsoft\\Updates" wide
      $s11 = "IoGetRelatedDeviceObject" fullword ascii
      $s12 = "VMEM.sys" fullword ascii
      $s13 = "RtlGetVersion" fullword wide
      $s14 = "ntkrnlpa.exe" fullword ascii
   condition: 
      uint32 ( 0 ) == 0xfedcbafe and filesize > 160KB and filesize < 200KB and all of ( $s* )
}