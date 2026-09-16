rule TTP_XOR_QUAD_CurrentVersionRun_5023 {
  strings:
    $key_5023 = { 03 4c [2] 27 42 [2] 0c 6e [2] 22 4c [2] 36 57 [2] 39 4d [2] 27 50 [2] 25 51 [2] 3e 57 [2] 22 50 [2] 3e 7f }

  condition:
    any of them
}