rule TTP_XOR_QUAD_CurrentVersionRun_4e4f {
  strings:
    $key_4e4f = { 1d 20 [2] 39 2e [2] 12 02 [2] 3c 20 [2] 28 3b [2] 27 21 [2] 39 3c [2] 3b 3d [2] 20 3b [2] 3c 3c [2] 20 13 }

  condition:
    any of them
}