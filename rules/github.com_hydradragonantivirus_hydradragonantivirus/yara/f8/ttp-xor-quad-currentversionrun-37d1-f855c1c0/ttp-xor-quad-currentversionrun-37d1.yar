rule TTP_XOR_QUAD_CurrentVersionRun_37d1 {
  strings:
    $key_37d1 = { 64 be [2] 40 b0 [2] 6b 9c [2] 45 be [2] 51 a5 [2] 5e bf [2] 40 a2 [2] 42 a3 [2] 59 a5 [2] 45 a2 [2] 59 8d }

  condition:
    any of them
}