rule TTP_XOR_QUAD_CurrentVersionRun_dc6c {
  strings:
    $key_dc6c = { 8f 03 [2] ab 0d [2] 80 21 [2] ae 03 [2] ba 18 [2] b5 02 [2] ab 1f [2] a9 1e [2] b2 18 [2] ae 1f [2] b2 30 }

  condition:
    any of them
}