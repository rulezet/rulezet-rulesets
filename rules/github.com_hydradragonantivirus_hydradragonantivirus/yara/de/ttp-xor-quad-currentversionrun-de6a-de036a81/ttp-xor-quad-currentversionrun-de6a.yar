rule TTP_XOR_QUAD_CurrentVersionRun_de6a {
  strings:
    $key_de6a = { 8d 05 [2] a9 0b [2] 82 27 [2] ac 05 [2] b8 1e [2] b7 04 [2] a9 19 [2] ab 18 [2] b0 1e [2] ac 19 [2] b0 36 }

  condition:
    any of them
}