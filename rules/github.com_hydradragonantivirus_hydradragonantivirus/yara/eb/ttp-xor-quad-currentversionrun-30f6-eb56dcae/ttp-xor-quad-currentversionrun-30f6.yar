rule TTP_XOR_QUAD_CurrentVersionRun_30f6 {
  strings:
    $key_30f6 = { 63 99 [2] 47 97 [2] 6c bb [2] 42 99 [2] 56 82 [2] 59 98 [2] 47 85 [2] 45 84 [2] 5e 82 [2] 42 85 [2] 5e aa }

  condition:
    any of them
}