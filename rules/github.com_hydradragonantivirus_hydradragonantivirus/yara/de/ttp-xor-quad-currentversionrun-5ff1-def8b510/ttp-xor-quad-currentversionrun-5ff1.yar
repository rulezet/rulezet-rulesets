rule TTP_XOR_QUAD_CurrentVersionRun_5ff1 {
  strings:
    $key_5ff1 = { 0c 9e [2] 28 90 [2] 03 bc [2] 2d 9e [2] 39 85 [2] 36 9f [2] 28 82 [2] 2a 83 [2] 31 85 [2] 2d 82 [2] 31 ad }

  condition:
    any of them
}