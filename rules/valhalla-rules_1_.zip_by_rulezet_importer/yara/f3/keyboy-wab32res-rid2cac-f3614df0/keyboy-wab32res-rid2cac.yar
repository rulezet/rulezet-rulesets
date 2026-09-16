rule KeyBoy_wab32res_RID2CAC : APT DEMO EXE FILE G0081 T1197 {
   meta:
      description = "Detects KeyBoy Loader wab32res.dll"
      author = "Markus Neis, Florian Roth"
      reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/tropic-trooper-new-strategy/"
      date = "2018-03-26 09:59:11"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "02281e26e89b61d84e2df66a0eeb729c5babd94607b1422505cd388843dd5456"
      hash2 = "fb9c9cbf6925de8c7b6ce8e7a8d5290e628be0b82a58f3e968426c0f734f38f6"
      tags = "APT, DEMO, EXE, FILE, G0081, T1197"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "B4490-2314-55C1- /Processid:{321bitsadmin /canceft\\windows\\curresoftware\\microso" fullword ascii
      $x2 = "D:\\Work\\VS\\House\\TSSL\\TSSL\\TClient" ascii
      $x3 = "\\Release\\FakeRun.pdb" ascii
      $x4 = "FakeRun.dll" fullword ascii
      $s1 = "cmd.exe /c \"%s\"" fullword ascii
      $s2 = "CreateProcess failed (%d)" fullword ascii
      $s3 = "CreateProcess %s " fullword ascii
      $s4 = "FindResource %s error " fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 1000KB and ( 1 of ( $x* ) or 4 of them )
}