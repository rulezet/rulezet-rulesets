rule TTP_XOR_QUAD_CurrentVersionRun_dc3a {
  strings:
    $key_dc3a = { 8f 55 [2] ab 5b [2] 80 77 [2] ae 55 [2] ba 4e [2] b5 54 [2] ab 49 [2] a9 48 [2] b2 4e [2] ae 49 [2] b2 66 }

  condition:
    any of them
}