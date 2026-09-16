rule TTP_XOR_QUAD_CurrentVersionRun_dc0a {
  strings:
    $key_dc0a = { 8f 65 [2] ab 6b [2] 80 47 [2] ae 65 [2] ba 7e [2] b5 64 [2] ab 79 [2] a9 78 [2] b2 7e [2] ae 79 [2] b2 56 }

  condition:
    any of them
}