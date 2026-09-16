rule TTP_XOR_QUAD_CurrentVersionRun_dc13 {
  strings:
    $key_dc13 = { 8f 7c [2] ab 72 [2] 80 5e [2] ae 7c [2] ba 67 [2] b5 7d [2] ab 60 [2] a9 61 [2] b2 67 [2] ae 60 [2] b2 4f }

  condition:
    any of them
}