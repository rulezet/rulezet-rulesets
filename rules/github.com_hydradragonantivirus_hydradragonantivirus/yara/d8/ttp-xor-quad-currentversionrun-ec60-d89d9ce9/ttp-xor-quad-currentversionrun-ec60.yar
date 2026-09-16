rule TTP_XOR_QUAD_CurrentVersionRun_ec60 {
  strings:
    $key_ec60 = { bf 0f [2] 9b 01 [2] b0 2d [2] 9e 0f [2] 8a 14 [2] 85 0e [2] 9b 13 [2] 99 12 [2] 82 14 [2] 9e 13 [2] 82 3c }

  condition:
    any of them
}