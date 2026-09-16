rule TTP_XOR_QUAD_CurrentVersionRun_de4e {
  strings:
    $key_de4e = { 8d 21 [2] a9 2f [2] 82 03 [2] ac 21 [2] b8 3a [2] b7 20 [2] a9 3d [2] ab 3c [2] b0 3a [2] ac 3d [2] b0 12 }

  condition:
    any of them
}