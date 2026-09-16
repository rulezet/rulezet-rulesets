rule Regin_Sample_1_RID2C57 : APT DEMO T1136 regin {
   meta:
      description = "Semiautomatically generated YARA rule - file-3665415_sys"
      author = "Florian Roth"
      reference = "-"
      date = "2014-11-25 09:45:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, T1136, regin"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Getting PortName/Identifier failed - %x" fullword ascii
      $s1 = "SerialAddDevice - error creating new devobj [%#08lx]" fullword ascii
      $s2 = "External Naming Failed - Status %x" fullword ascii
      $s3 = "------- Same multiport - different interrupts" fullword ascii
      $s4 = "%x occurred prior to the wait - starting the" fullword ascii
      $s5 = "'user registry info - userPortIndex: %d" fullword ascii
      $s6 = "Could not report legacy device - %x" fullword ascii
      $s7 = "entering SerialGetPortInfo" fullword ascii
      $s8 = "'user registry info - userPort: %x" fullword ascii
      $s9 = "IoOpenDeviceRegistryKey failed - %x " fullword ascii
      $s10 = "Kernel debugger is using port at address %X" fullword ascii
      $s12 = "Release - freeing multi context" fullword ascii
      $s13 = "Serial driver will not load port" fullword ascii
      $s14 = "'user registry info - userAddressSpace: %d" fullword ascii
      $s15 = "SerialAddDevice: Enumeration request, returning NO_MORE_ENTRIES" fullword ascii
      $s20 = "'user registry info - userIndexed: %d" fullword ascii
      $fp1 = "Enter SerialBuildResourceList" ascii fullword
   condition: 
      filesize < 110KB and filesize > 80KB and all of them and not $fp1
}