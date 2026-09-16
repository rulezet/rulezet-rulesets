rule TTP_XOR_QUAD_CurrentVersionRun_dcf4 {
  strings:
    $key_dcf4 = { 8f 9b [2] ab 95 [2] 80 b9 [2] ae 9b [2] ba 80 [2] b5 9a [2] ab 87 [2] a9 86 [2] b2 80 [2] ae 87 [2] b2 a8 }

  condition:
    any of them
}