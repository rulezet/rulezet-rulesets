rule TTP_XOR_QUAD_CurrentVersionRun_1bf1 {
  strings:
    $key_1bf1 = { 48 9e [2] 6c 90 [2] 47 bc [2] 69 9e [2] 7d 85 [2] 72 9f [2] 6c 82 [2] 6e 83 [2] 75 85 [2] 69 82 [2] 75 ad }

  condition:
    any of them
}