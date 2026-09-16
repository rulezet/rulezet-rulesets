rule TTP_XOR_QUAD_CurrentVersionRun_e224 {
  strings:
    $key_e224 = { b1 4b [2] 95 45 [2] be 69 [2] 90 4b [2] 84 50 [2] 8b 4a [2] 95 57 [2] 97 56 [2] 8c 50 [2] 90 57 [2] 8c 78 }

  condition:
    any of them
}