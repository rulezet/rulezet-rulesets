rule TTP_XOR_QUAD_CurrentVersionRun_5af1 {
  strings:
    $key_5af1 = { 09 9e [2] 2d 90 [2] 06 bc [2] 28 9e [2] 3c 85 [2] 33 9f [2] 2d 82 [2] 2f 83 [2] 34 85 [2] 28 82 [2] 34 ad }

  condition:
    any of them
}