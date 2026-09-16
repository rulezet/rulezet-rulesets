rule TTP_XOR_QUAD_CurrentVersionRun_af32 {
  strings:
    $key_af32 = { fc 5d [2] d8 53 [2] f3 7f [2] dd 5d [2] c9 46 [2] c6 5c [2] d8 41 [2] da 40 [2] c1 46 [2] dd 41 [2] c1 6e }

  condition:
    any of them
}