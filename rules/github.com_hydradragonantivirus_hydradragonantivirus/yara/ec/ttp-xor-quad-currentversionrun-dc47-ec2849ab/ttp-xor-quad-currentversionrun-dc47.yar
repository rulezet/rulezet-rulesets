rule TTP_XOR_QUAD_CurrentVersionRun_dc47 {
  strings:
    $key_dc47 = { 8f 28 [2] ab 26 [2] 80 0a [2] ae 28 [2] ba 33 [2] b5 29 [2] ab 34 [2] a9 35 [2] b2 33 [2] ae 34 [2] b2 1b }

  condition:
    any of them
}