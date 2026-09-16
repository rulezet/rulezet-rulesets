rule TTP_XOR_QUAD_CurrentVersionRun_7af1 {
  strings:
    $key_7af1 = { 29 9e [2] 0d 90 [2] 26 bc [2] 08 9e [2] 1c 85 [2] 13 9f [2] 0d 82 [2] 0f 83 [2] 14 85 [2] 08 82 [2] 14 ad }

  condition:
    any of them
}