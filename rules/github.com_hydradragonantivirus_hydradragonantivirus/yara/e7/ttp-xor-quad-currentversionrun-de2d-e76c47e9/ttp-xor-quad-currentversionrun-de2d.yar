rule TTP_XOR_QUAD_CurrentVersionRun_de2d {
  strings:
    $key_de2d = { 8d 42 [2] a9 4c [2] 82 60 [2] ac 42 [2] b8 59 [2] b7 43 [2] a9 5e [2] ab 5f [2] b0 59 [2] ac 5e [2] b0 71 }

  condition:
    any of them
}