rule EquationGroup_curseflower_mswin32_v_1_0_0 {
   meta:
      description = "Equation Group hack tool set"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
      date = "2017-04-09"
      hash1 = "fdc452629ff7befe02adea3a135c3744d8585af890a4301b2a10a817e48c5cbf"
      id = "4138f87a-4584-5efc-a168-633838893e2f"
   strings:
      $s1 = "<pVt,<et(<st$<ct$<nt" fullword ascii

      $op1 = { 6a 04 83 c0 08 6a 01 50 e8 10 34 00 00 83 c4 10 } 
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}