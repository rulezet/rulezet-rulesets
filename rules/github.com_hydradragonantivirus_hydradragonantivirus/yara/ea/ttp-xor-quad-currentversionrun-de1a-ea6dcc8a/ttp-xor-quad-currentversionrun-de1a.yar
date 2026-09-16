rule TTP_XOR_QUAD_CurrentVersionRun_de1a {
  strings:
    $key_de1a = { 8d 75 [2] a9 7b [2] 82 57 [2] ac 75 [2] b8 6e [2] b7 74 [2] a9 69 [2] ab 68 [2] b0 6e [2] ac 69 [2] b0 46 }

  condition:
    any of them
}