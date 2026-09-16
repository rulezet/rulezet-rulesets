import "pe"
rule SUSP_Fake_AMSI_DLL_Jun23_1_RID2F77 : DEMO EXE FILE SUSP {
   meta:
      description = "Detects an amsi.dll that has the same exports as the legitimate one but very different contents or file sizes"
      author = "Florian Roth"
      reference = "https://twitter.com/eversinc33/status/1666121784192581633?s=20"
      date = "2023-06-07 11:58:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-06-12"
      tags = "DEMO, EXE, FILE, SUSP"
      required_modules = "pe"
      minimum_yara = "3.6.0"
      
   strings:
      $a1 = "Microsoft.Antimalware.Scan.Interface" ascii
      $a2 = "Amsi.pdb" ascii fullword
      $a3 = "api-ms-win-core-sysinfo-" ascii
      $a4 = "Software\\Microsoft\\AMSI\\Providers" wide
      $a5 = "AmsiAntimalware@" ascii
      $a6 = "AMSI UAC Scan" ascii
      $fp1 = "Wine builtin DLL" 
   condition: 
      uint16 ( 0 ) == 0x5a4d and ( pe.exports ( "AmsiInitialize" ) and pe.exports ( "AmsiScanString" ) ) and ( filesize > 200KB or filesize < 35KB or not 4 of ( $a* ) ) and not 1 of ( $fp* )
}