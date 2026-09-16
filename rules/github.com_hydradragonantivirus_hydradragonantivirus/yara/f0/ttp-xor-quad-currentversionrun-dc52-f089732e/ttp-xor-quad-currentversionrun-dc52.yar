rule TTP_XOR_QUAD_CurrentVersionRun_dc52 {
  strings:
    $key_dc52 = { 8f 3d [2] ab 33 [2] 80 1f [2] ae 3d [2] ba 26 [2] b5 3c [2] ab 21 [2] a9 20 [2] b2 26 [2] ae 21 [2] b2 0e }

  condition:
    any of them
}