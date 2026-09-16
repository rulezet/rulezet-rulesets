rule TTP_XOR_QUAD_CurrentVersionRun_aacd {
  strings:
    $key_aacd = { f9 a2 [2] dd ac [2] f6 80 [2] d8 a2 [2] cc b9 [2] c3 a3 [2] dd be [2] df bf [2] c4 b9 [2] d8 be [2] c4 91 }

  condition:
    any of them
}