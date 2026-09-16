rule ShellCrew_StreamEx_1_RID2EB2 : APT DEMO EXE FILE G0009 {
   meta:
      description = "Semiautomatically generated YARA rule"
      author = "Florian Roth"
      reference = "https://blog.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar"
      date = "2017-02-10 11:25:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2022-12-21"
      hash1 = "81f411415aefa5ad7f7ed2365d9a18d0faf33738617afc19215b69c23f212c07"
      tags = "APT, DEMO, EXE, FILE, G0009"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "cmd.exe /c  \"%s\"" fullword wide
      $s3 = "uac\\bin\\install_test.pdb" ascii
      $s5 = "uncompress error:%d %s" fullword ascii
      $s7 = "%s\\AdobeBak\\Proc.dat" fullword wide
      $s8 = "e:\\workspace\\boar" fullword ascii
      $s12 = "$\\data.ini" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and 4 of them )
}