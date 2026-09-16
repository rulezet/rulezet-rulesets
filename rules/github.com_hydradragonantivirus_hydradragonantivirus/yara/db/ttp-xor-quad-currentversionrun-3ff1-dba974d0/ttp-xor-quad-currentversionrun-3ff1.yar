rule TTP_XOR_QUAD_CurrentVersionRun_3ff1 {
  strings:
    $key_3ff1 = { 6c 9e [2] 48 90 [2] 63 bc [2] 4d 9e [2] 59 85 [2] 56 9f [2] 48 82 [2] 4a 83 [2] 51 85 [2] 4d 82 [2] 51 ad }

  condition:
    any of them
}