rule TTP_XOR_QUAD_CurrentVersionRun_dc64 {
  strings:
    $key_dc64 = { 8f 0b [2] ab 05 [2] 80 29 [2] ae 0b [2] ba 10 [2] b5 0a [2] ab 17 [2] a9 16 [2] b2 10 [2] ae 17 [2] b2 38 }

  condition:
    any of them
}