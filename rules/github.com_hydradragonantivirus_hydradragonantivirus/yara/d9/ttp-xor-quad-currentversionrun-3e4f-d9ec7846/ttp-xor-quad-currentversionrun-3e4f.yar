rule TTP_XOR_QUAD_CurrentVersionRun_3e4f {
  strings:
    $key_3e4f = { 6d 20 [2] 49 2e [2] 62 02 [2] 4c 20 [2] 58 3b [2] 57 21 [2] 49 3c [2] 4b 3d [2] 50 3b [2] 4c 3c [2] 50 13 }

  condition:
    any of them
}