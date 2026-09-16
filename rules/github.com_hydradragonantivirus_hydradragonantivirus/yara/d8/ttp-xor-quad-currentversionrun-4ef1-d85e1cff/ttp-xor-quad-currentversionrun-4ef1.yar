rule TTP_XOR_QUAD_CurrentVersionRun_4ef1 {
  strings:
    $key_4ef1 = { 1d 9e [2] 39 90 [2] 12 bc [2] 3c 9e [2] 28 85 [2] 27 9f [2] 39 82 [2] 3b 83 [2] 20 85 [2] 3c 82 [2] 20 ad }

  condition:
    any of them
}