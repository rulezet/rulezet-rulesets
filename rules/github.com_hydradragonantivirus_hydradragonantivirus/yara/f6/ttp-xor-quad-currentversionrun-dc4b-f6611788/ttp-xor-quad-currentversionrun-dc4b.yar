rule TTP_XOR_QUAD_CurrentVersionRun_dc4b {
  strings:
    $key_dc4b = { 8f 24 [2] ab 2a [2] 80 06 [2] ae 24 [2] ba 3f [2] b5 25 [2] ab 38 [2] a9 39 [2] b2 3f [2] ae 38 [2] b2 17 }

  condition:
    any of them
}