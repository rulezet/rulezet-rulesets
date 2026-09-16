rule Msfpayloads_msf_8_RID2DD0 : APT DEMO METASPLOIT SCRIPT T1059_001 {
   meta:
      description = "Metasploit Payloads - file msf.ps1"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-02-09 10:47:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "519717e01f0cb3f460ef88cd70c3de8c7f00fb7c564260bd2908e97d11fde87f"
      tags = "APT, DEMO, METASPLOIT, SCRIPT, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "[DllImport(\"kernel32.dll\")]" fullword ascii
      $s2 = "[DllImport(\"msvcrt.dll\")]" fullword ascii
      $s3 = "-Name \"Win32\" -namespace Win32Functions -passthru" fullword ascii
      $s4 = "::VirtualAlloc(0,[Math]::Max($" ascii
      $s5 = ".Length,0x1000),0x3000,0x40)" ascii
      $s6 = "public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" fullword ascii
      $s7 = "::memset([IntPtr]($" ascii
   condition: 
      6 of them
}