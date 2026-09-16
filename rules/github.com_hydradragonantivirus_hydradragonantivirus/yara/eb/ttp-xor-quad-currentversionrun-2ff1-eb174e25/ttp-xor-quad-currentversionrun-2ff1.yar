rule TTP_XOR_QUAD_CurrentVersionRun_2ff1 {
  strings:
    $key_2ff1 = { 7c 9e [2] 58 90 [2] 73 bc [2] 5d 9e [2] 49 85 [2] 46 9f [2] 58 82 [2] 5a 83 [2] 41 85 [2] 5d 82 [2] 41 ad }

  condition:
    any of them
}