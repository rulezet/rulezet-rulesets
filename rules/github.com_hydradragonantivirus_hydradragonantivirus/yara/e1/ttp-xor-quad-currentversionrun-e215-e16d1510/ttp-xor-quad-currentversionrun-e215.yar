rule TTP_XOR_QUAD_CurrentVersionRun_e215 {
  strings:
    $key_e215 = { b1 7a [2] 95 74 [2] be 58 [2] 90 7a [2] 84 61 [2] 8b 7b [2] 95 66 [2] 97 67 [2] 8c 61 [2] 90 66 [2] 8c 49 }

  condition:
    any of them
}