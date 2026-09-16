rule TTP_XOR_QUAD_CurrentVersionRun_3af1 {
  strings:
    $key_3af1 = { 69 9e [2] 4d 90 [2] 66 bc [2] 48 9e [2] 5c 85 [2] 53 9f [2] 4d 82 [2] 4f 83 [2] 54 85 [2] 48 82 [2] 54 ad }

  condition:
    any of them
}