rule TTP_XOR_QUAD_CurrentVersionRun_dc5d {
  strings:
    $key_dc5d = { 8f 32 [2] ab 3c [2] 80 10 [2] ae 32 [2] ba 29 [2] b5 33 [2] ab 2e [2] a9 2f [2] b2 29 [2] ae 2e [2] b2 01 }

  condition:
    any of them
}