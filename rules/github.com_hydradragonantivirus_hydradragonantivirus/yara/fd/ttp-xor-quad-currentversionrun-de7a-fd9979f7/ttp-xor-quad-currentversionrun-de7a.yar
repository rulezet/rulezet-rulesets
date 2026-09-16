rule TTP_XOR_QUAD_CurrentVersionRun_de7a {
  strings:
    $key_de7a = { 8d 15 [2] a9 1b [2] 82 37 [2] ac 15 [2] b8 0e [2] b7 14 [2] a9 09 [2] ab 08 [2] b0 0e [2] ac 09 [2] b0 26 }

  condition:
    any of them
}