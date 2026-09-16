rule SUSP_Fake_AMSI_DLL_Jun23_2 {
   meta:
      description = "Detects an amsi.dll that has very different contents or file sizes than the legitimate"
      author = "Florian Roth"
      reference = "https://twitter.com/eversinc33/status/1666121784192581633?s=20"
      date = "2023-06-07"
      modified = "2023-06-14"
      score = 65
      id = "adec9525-6299-52d5-8f4e-a83366d3dcfd"
   strings:
      $a1 = "Microsoft.Antimalware.Scan.Interface" ascii
      $a2 = "Amsi.pdb" ascii fullword
      $a3 = "api-ms-win-core-sysinfo-" ascii
      $a4 = "Software\\Microsoft\\AMSI\\Providers" wide
      $a5 = "AmsiAntimalware@" ascii
      $a6 = "AMSI UAC Scan" ascii

      $fp1 = "Wine builtin DLL"
   condition:
      uint16(0) == 0x5a4d 
            and filename == "amsi.dll"
            and (
         filesize > 200KB              or filesize < 35KB            or not 4 of ($a*)        )
      and not 1 of ($fp*)
}