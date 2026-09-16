rule TTP_XOR_QUAD_CurrentVersionRun_6b13 {
  strings:
    $key_6b13 = { 38 7c [2] 1c 72 [2] 37 5e [2] 19 7c [2] 0d 67 [2] 02 7d [2] 1c 60 [2] 1e 61 [2] 05 67 [2] 19 60 [2] 05 4f }

  condition:
    any of them
}