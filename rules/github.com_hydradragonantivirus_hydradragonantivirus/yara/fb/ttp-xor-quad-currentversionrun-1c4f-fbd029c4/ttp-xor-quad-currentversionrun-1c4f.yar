rule TTP_XOR_QUAD_CurrentVersionRun_1c4f {
  strings:
    $key_1c4f = { 4f 20 [2] 6b 2e [2] 40 02 [2] 6e 20 [2] 7a 3b [2] 75 21 [2] 6b 3c [2] 69 3d [2] 72 3b [2] 6e 3c [2] 72 13 }

  condition:
    any of them
}