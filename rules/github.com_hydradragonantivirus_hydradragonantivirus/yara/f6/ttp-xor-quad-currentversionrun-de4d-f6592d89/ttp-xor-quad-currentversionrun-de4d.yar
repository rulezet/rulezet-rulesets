rule TTP_XOR_QUAD_CurrentVersionRun_de4d {
  strings:
    $key_de4d = { 8d 22 [2] a9 2c [2] 82 00 [2] ac 22 [2] b8 39 [2] b7 23 [2] a9 3e [2] ab 3f [2] b0 39 [2] ac 3e [2] b0 11 }

  condition:
    any of them
}