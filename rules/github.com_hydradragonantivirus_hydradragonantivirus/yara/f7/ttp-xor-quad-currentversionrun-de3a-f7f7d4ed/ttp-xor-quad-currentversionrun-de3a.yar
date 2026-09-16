rule TTP_XOR_QUAD_CurrentVersionRun_de3a {
  strings:
    $key_de3a = { 8d 55 [2] a9 5b [2] 82 77 [2] ac 55 [2] b8 4e [2] b7 54 [2] a9 49 [2] ab 48 [2] b0 4e [2] ac 49 [2] b0 66 }

  condition:
    any of them
}