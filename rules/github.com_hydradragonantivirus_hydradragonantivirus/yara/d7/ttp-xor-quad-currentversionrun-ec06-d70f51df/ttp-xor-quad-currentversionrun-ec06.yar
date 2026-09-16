rule TTP_XOR_QUAD_CurrentVersionRun_ec06 {
  strings:
    $key_ec06 = { bf 69 [2] 9b 67 [2] b0 4b [2] 9e 69 [2] 8a 72 [2] 85 68 [2] 9b 75 [2] 99 74 [2] 82 72 [2] 9e 75 [2] 82 5a }

  condition:
    any of them
}