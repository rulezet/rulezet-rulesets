rule TTP_XOR_QUAD_CurrentVersionRun_05d1 {
  strings:
    $key_05d1 = { 56 be [2] 72 b0 [2] 59 9c [2] 77 be [2] 63 a5 [2] 6c bf [2] 72 a2 [2] 70 a3 [2] 6b a5 [2] 77 a2 [2] 6b 8d }

  condition:
    any of them
}