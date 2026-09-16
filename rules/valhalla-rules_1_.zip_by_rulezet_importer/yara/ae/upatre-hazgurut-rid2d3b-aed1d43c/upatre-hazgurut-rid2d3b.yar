rule Upatre_Hazgurut_RID2D3B : DEMO EXE FILE MAL {
   meta:
      description = "Detects Upatre malware dropped by Downloader - file hazgurut.exe"
      author = "Florian Roth"
      reference = "https://weankor.vxstream-sandbox.com/sample/6b857ef314938d37997c178ea50687a281d8ff9925f0c4e70940754643e2c0e3?environmentId=7"
      date = "2015-10-13 10:23:01"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "7ee0d20b15e24b7fe72154d9521e1959752b4e9c20d2992500df9ac096450a50"
      hash2 = "79ffc620ddb143525fa32bc6a83c636168501a4a589a38cdb0a74afac1ee8b92"
      hash3 = "62d8a6880c594fe9529158b94a9336179fa7a3d3bf1aa9d0baaf07d03b281bd3"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "barcod" fullword ascii
      $s0 = "msports.dll" fullword ascii
      $s1 = "nddeapi.dll" fullword ascii
      $s2 = "glmf32.dll" fullword ascii
      $s3 = "<requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\">" fullword ascii
      $s4 = "cmutil.dll" fullword ascii
      $s5 = "mprapi.dll" fullword ascii
      $s6 = "glmf32.dll" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1500KB and $a1 in ( 0 .. 4000 ) and all of ( $s* )
}