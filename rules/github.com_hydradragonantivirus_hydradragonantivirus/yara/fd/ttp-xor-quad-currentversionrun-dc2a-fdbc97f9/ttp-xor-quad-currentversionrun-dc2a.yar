rule TTP_XOR_QUAD_CurrentVersionRun_dc2a {
  strings:
    $key_dc2a = { 8f 45 [2] ab 4b [2] 80 67 [2] ae 45 [2] ba 5e [2] b5 44 [2] ab 59 [2] a9 58 [2] b2 5e [2] ae 59 [2] b2 76 }

  condition:
    any of them
}