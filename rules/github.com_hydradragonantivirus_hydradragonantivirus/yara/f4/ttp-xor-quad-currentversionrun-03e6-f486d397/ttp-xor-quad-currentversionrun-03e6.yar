rule TTP_XOR_QUAD_CurrentVersionRun_03e6 {
  strings:
    $key_03e6 = { 50 89 [2] 74 87 [2] 5f ab [2] 71 89 [2] 65 92 [2] 6a 88 [2] 74 95 [2] 76 94 [2] 6d 92 [2] 71 95 [2] 6d ba }

  condition:
    any of them
}