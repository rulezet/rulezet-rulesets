rule TTP_XOR_QUAD_CurrentVersionRun_03d1 {
  strings:
    $key_03d1 = { 50 be [2] 74 b0 [2] 5f 9c [2] 71 be [2] 65 a5 [2] 6a bf [2] 74 a2 [2] 76 a3 [2] 6d a5 [2] 71 a2 [2] 6d 8d }

  condition:
    any of them
}