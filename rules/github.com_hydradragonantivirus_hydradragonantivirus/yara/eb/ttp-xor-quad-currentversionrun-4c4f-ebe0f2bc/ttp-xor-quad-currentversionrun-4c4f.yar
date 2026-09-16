rule TTP_XOR_QUAD_CurrentVersionRun_4c4f {
  strings:
    $key_4c4f = { 1f 20 [2] 3b 2e [2] 10 02 [2] 3e 20 [2] 2a 3b [2] 25 21 [2] 3b 3c [2] 39 3d [2] 22 3b [2] 3e 3c [2] 22 13 }

  condition:
    any of them
}