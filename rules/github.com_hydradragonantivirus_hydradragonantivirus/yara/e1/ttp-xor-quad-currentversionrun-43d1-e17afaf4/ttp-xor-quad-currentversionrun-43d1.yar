rule TTP_XOR_QUAD_CurrentVersionRun_43d1 {
  strings:
    $key_43d1 = { 10 be [2] 34 b0 [2] 1f 9c [2] 31 be [2] 25 a5 [2] 2a bf [2] 34 a2 [2] 36 a3 [2] 2d a5 [2] 31 a2 [2] 2d 8d }

  condition:
    any of them
}