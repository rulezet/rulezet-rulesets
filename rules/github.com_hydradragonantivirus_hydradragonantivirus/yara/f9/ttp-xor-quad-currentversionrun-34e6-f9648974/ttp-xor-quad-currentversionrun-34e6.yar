rule TTP_XOR_QUAD_CurrentVersionRun_34e6 {
  strings:
    $key_34e6 = { 67 89 [2] 43 87 [2] 68 ab [2] 46 89 [2] 52 92 [2] 5d 88 [2] 43 95 [2] 41 94 [2] 5a 92 [2] 46 95 [2] 5a ba }

  condition:
    any of them
}