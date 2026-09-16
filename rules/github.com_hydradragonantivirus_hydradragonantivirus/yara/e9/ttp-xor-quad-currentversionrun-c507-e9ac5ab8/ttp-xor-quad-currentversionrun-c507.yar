rule TTP_XOR_QUAD_CurrentVersionRun_c507 {
  strings:
    $key_c507 = { 96 68 [2] b2 66 [2] 99 4a [2] b7 68 [2] a3 73 [2] ac 69 [2] b2 74 [2] b0 75 [2] ab 73 [2] b7 74 [2] ab 5b }

  condition:
    any of them
}