rule TTP_XOR_QUAD_CurrentVersionRun_dcfb {
  strings:
    $key_dcfb = { 8f 94 [2] ab 9a [2] 80 b6 [2] ae 94 [2] ba 8f [2] b5 95 [2] ab 88 [2] a9 89 [2] b2 8f [2] ae 88 [2] b2 a7 }

  condition:
    any of them
}