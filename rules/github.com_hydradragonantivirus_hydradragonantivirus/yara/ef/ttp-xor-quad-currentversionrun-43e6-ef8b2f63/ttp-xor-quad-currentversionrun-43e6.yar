rule TTP_XOR_QUAD_CurrentVersionRun_43e6 {
  strings:
    $key_43e6 = { 10 89 [2] 34 87 [2] 1f ab [2] 31 89 [2] 25 92 [2] 2a 88 [2] 34 95 [2] 36 94 [2] 2d 92 [2] 31 95 [2] 2d ba }

  condition:
    any of them
}