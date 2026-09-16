rule TTP_XOR_QUAD_CurrentVersionRun_de4f {
  strings:
    $key_de4f = { 8d 20 [2] a9 2e [2] 82 02 [2] ac 20 [2] b8 3b [2] b7 21 [2] a9 3c [2] ab 3d [2] b0 3b [2] ac 3c [2] b0 13 }

  condition:
    any of them
}