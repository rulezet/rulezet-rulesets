rule EquationGroup_curseflower_mswin32_v_1_0_0_RID36E9 : APT DEMO EXE FILE G0020 {
   meta:
      description = "Equation Group hack tool set"
      author = "Florian Roth"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09 17:16:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "fdc452629ff7befe02adea3a135c3744d8585af890a4301b2a10a817e48c5cbf"
      tags = "APT, DEMO, EXE, FILE, G0020"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<pVt,<et(<st$<ct$<nt" fullword ascii
      $op1 = { 6a 04 83 c0 08 6a 01 50 e8 10 34 00 00 83 c4 10 } 
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 300KB and all of them )
}