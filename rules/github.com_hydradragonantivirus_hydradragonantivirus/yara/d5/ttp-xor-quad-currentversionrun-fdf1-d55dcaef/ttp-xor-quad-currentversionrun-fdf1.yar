rule TTP_XOR_QUAD_CurrentVersionRun_fdf1 {
  strings:
    $key_fdf1 = { ae 9e [2] 8a 90 [2] a1 bc [2] 8f 9e [2] 9b 85 [2] 94 9f [2] 8a 82 [2] 88 83 [2] 93 85 [2] 8f 82 [2] 93 ad }

  condition:
    any of them
}