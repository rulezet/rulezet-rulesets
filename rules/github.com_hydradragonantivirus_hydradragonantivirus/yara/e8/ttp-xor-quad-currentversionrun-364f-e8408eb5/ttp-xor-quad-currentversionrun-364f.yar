rule TTP_XOR_QUAD_CurrentVersionRun_364f {
  strings:
    $key_364f = { 65 20 [2] 41 2e [2] 6a 02 [2] 44 20 [2] 50 3b [2] 5f 21 [2] 41 3c [2] 43 3d [2] 58 3b [2] 44 3c [2] 58 13 }

  condition:
    any of them
}