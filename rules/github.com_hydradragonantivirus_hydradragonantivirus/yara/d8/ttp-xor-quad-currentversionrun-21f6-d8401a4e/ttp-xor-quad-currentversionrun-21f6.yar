rule TTP_XOR_QUAD_CurrentVersionRun_21f6 {
  strings:
    $key_21f6 = { 72 99 [2] 56 97 [2] 7d bb [2] 53 99 [2] 47 82 [2] 48 98 [2] 56 85 [2] 54 84 [2] 4f 82 [2] 53 85 [2] 4f aa }

  condition:
    any of them
}