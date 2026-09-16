rule TTP_XOR_QUAD_CurrentVersionRun_3d23 {
  strings:
    $key_3d23 = { 6e 4c [2] 4a 42 [2] 61 6e [2] 4f 4c [2] 5b 57 [2] 54 4d [2] 4a 50 [2] 48 51 [2] 53 57 [2] 4f 50 [2] 53 7f }

  condition:
    any of them
}