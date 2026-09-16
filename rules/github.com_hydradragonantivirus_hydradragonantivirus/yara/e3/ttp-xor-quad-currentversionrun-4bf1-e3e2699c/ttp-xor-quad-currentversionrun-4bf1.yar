rule TTP_XOR_QUAD_CurrentVersionRun_4bf1 {
  strings:
    $key_4bf1 = { 18 9e [2] 3c 90 [2] 17 bc [2] 39 9e [2] 2d 85 [2] 22 9f [2] 3c 82 [2] 3e 83 [2] 25 85 [2] 39 82 [2] 25 ad }

  condition:
    any of them
}