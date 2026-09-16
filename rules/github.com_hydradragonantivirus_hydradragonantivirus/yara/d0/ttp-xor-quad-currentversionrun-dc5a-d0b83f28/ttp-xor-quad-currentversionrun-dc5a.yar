rule TTP_XOR_QUAD_CurrentVersionRun_dc5a {
  strings:
    $key_dc5a = { 8f 35 [2] ab 3b [2] 80 17 [2] ae 35 [2] ba 2e [2] b5 34 [2] ab 29 [2] a9 28 [2] b2 2e [2] ae 29 [2] b2 06 }

  condition:
    any of them
}