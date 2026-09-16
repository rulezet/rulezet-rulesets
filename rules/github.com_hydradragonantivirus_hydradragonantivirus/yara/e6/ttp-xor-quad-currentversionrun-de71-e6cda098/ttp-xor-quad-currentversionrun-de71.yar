rule TTP_XOR_QUAD_CurrentVersionRun_de71 {
  strings:
    $key_de71 = { 8d 1e [2] a9 10 [2] 82 3c [2] ac 1e [2] b8 05 [2] b7 1f [2] a9 02 [2] ab 03 [2] b0 05 [2] ac 02 [2] b0 2d }

  condition:
    any of them
}