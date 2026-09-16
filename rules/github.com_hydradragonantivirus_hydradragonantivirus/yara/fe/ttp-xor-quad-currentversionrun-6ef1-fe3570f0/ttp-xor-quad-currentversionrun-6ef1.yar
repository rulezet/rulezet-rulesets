rule TTP_XOR_QUAD_CurrentVersionRun_6ef1 {
  strings:
    $key_6ef1 = { 3d 9e [2] 19 90 [2] 32 bc [2] 1c 9e [2] 08 85 [2] 07 9f [2] 19 82 [2] 1b 83 [2] 00 85 [2] 1c 82 [2] 00 ad }

  condition:
    any of them
}