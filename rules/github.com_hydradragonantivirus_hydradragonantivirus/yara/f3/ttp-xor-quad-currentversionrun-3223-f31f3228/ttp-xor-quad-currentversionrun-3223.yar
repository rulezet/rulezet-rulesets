rule TTP_XOR_QUAD_CurrentVersionRun_3223 {
  strings:
    $key_3223 = { 61 4c [2] 45 42 [2] 6e 6e [2] 40 4c [2] 54 57 [2] 5b 4d [2] 45 50 [2] 47 51 [2] 5c 57 [2] 40 50 [2] 5c 7f }

  condition:
    any of them
}