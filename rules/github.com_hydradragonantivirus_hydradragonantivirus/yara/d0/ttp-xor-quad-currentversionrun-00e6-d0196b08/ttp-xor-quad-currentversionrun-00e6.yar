rule TTP_XOR_QUAD_CurrentVersionRun_00e6 {
  strings:
    $key_00e6 = { 53 89 [2] 77 87 [2] 5c ab [2] 72 89 [2] 66 92 [2] 69 88 [2] 77 95 [2] 75 94 [2] 6e 92 [2] 72 95 [2] 6e ba }

  condition:
    any of them
}