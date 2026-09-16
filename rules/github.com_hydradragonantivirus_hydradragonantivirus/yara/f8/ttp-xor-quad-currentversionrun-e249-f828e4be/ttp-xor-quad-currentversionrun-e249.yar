rule TTP_XOR_QUAD_CurrentVersionRun_e249 {
  strings:
    $key_e249 = { b1 26 [2] 95 28 [2] be 04 [2] 90 26 [2] 84 3d [2] 8b 27 [2] 95 3a [2] 97 3b [2] 8c 3d [2] 90 3a [2] 8c 15 }

  condition:
    any of them
}