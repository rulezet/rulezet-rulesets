rule TTP_XOR_QUAD_CurrentVersionRun_224f {
  strings:
    $key_224f = { 71 20 [2] 55 2e [2] 7e 02 [2] 50 20 [2] 44 3b [2] 4b 21 [2] 55 3c [2] 57 3d [2] 4c 3b [2] 50 3c [2] 4c 13 }

  condition:
    any of them
}