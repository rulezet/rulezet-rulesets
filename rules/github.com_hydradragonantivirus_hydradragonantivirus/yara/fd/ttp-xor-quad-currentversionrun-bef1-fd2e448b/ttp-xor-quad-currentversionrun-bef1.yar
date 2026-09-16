rule TTP_XOR_QUAD_CurrentVersionRun_bef1 {
  strings:
    $key_bef1 = { ed 9e [2] c9 90 [2] e2 bc [2] cc 9e [2] d8 85 [2] d7 9f [2] c9 82 [2] cb 83 [2] d0 85 [2] cc 82 [2] d0 ad }

  condition:
    any of them
}