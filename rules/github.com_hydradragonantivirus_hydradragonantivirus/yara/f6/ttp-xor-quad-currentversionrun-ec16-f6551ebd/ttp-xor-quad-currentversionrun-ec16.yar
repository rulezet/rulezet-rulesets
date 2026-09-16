rule TTP_XOR_QUAD_CurrentVersionRun_ec16 {
  strings:
    $key_ec16 = { bf 79 [2] 9b 77 [2] b0 5b [2] 9e 79 [2] 8a 62 [2] 85 78 [2] 9b 65 [2] 99 64 [2] 82 62 [2] 9e 65 [2] 82 4a }

  condition:
    any of them
}