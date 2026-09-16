rule TTP_XOR_QUAD_CurrentVersionRun_0c4f {
  strings:
    $key_0c4f = { 5f 20 [2] 7b 2e [2] 50 02 [2] 7e 20 [2] 6a 3b [2] 65 21 [2] 7b 3c [2] 79 3d [2] 62 3b [2] 7e 3c [2] 62 13 }

  condition:
    any of them
}