rule TTP_XOR_QUAD_CurrentVersionRun_dc6d {
  strings:
    $key_dc6d = { 8f 02 [2] ab 0c [2] 80 20 [2] ae 02 [2] ba 19 [2] b5 03 [2] ab 1e [2] a9 1f [2] b2 19 [2] ae 1e [2] b2 31 }

  condition:
    any of them
}