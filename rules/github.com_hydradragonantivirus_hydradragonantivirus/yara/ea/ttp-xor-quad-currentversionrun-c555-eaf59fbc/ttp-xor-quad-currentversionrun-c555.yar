rule TTP_XOR_QUAD_CurrentVersionRun_c555 {
  strings:
    $key_c555 = { 96 3a [2] b2 34 [2] 99 18 [2] b7 3a [2] a3 21 [2] ac 3b [2] b2 26 [2] b0 27 [2] ab 21 [2] b7 26 [2] ab 09 }

  condition:
    any of them
}