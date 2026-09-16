rule TTP_XOR_QUAD_CurrentVersionRun_63e6 {
  strings:
    $key_63e6 = { 30 89 [2] 14 87 [2] 3f ab [2] 11 89 [2] 05 92 [2] 0a 88 [2] 14 95 [2] 16 94 [2] 0d 92 [2] 11 95 [2] 0d ba }

  condition:
    any of them
}