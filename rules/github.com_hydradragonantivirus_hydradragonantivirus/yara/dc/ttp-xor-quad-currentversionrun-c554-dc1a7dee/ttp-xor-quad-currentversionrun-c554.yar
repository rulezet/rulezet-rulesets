rule TTP_XOR_QUAD_CurrentVersionRun_c554 {
  strings:
    $key_c554 = { 96 3b [2] b2 35 [2] 99 19 [2] b7 3b [2] a3 20 [2] ac 3a [2] b2 27 [2] b0 26 [2] ab 20 [2] b7 27 [2] ab 08 }

  condition:
    any of them
}