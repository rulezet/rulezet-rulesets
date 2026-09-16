rule TTP_XOR_QUAD_CurrentVersionRun_dc70 {
  strings:
    $key_dc70 = { 8f 1f [2] ab 11 [2] 80 3d [2] ae 1f [2] ba 04 [2] b5 1e [2] ab 03 [2] a9 02 [2] b2 04 [2] ae 03 [2] b2 2c }

  condition:
    any of them
}