rule TTP_XOR_QUAD_CurrentVersionRun_367f {
  strings:
    $key_367f = { 65 10 [2] 41 1e [2] 6a 32 [2] 44 10 [2] 50 0b [2] 5f 11 [2] 41 0c [2] 43 0d [2] 58 0b [2] 44 0c [2] 58 23 }

  condition:
    any of them
}