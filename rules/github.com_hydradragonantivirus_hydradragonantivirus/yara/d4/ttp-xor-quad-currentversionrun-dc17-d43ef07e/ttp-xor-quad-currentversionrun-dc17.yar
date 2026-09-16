rule TTP_XOR_QUAD_CurrentVersionRun_dc17 {
  strings:
    $key_dc17 = { 8f 78 [2] ab 76 [2] 80 5a [2] ae 78 [2] ba 63 [2] b5 79 [2] ab 64 [2] a9 65 [2] b2 63 [2] ae 64 [2] b2 4b }

  condition:
    any of them
}