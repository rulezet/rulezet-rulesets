rule TTP_XOR_QUAD_CurrentVersionRun_71f6 {
  strings:
    $key_71f6 = { 22 99 [2] 06 97 [2] 2d bb [2] 03 99 [2] 17 82 [2] 18 98 [2] 06 85 [2] 04 84 [2] 1f 82 [2] 03 85 [2] 1f aa }

  condition:
    any of them
}