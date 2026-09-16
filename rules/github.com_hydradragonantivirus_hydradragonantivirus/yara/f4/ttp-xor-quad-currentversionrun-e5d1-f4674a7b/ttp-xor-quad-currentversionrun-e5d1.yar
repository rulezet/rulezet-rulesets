rule TTP_XOR_QUAD_CurrentVersionRun_e5d1 {
  strings:
    $key_e5d1 = { b6 be [2] 92 b0 [2] b9 9c [2] 97 be [2] 83 a5 [2] 8c bf [2] 92 a2 [2] 90 a3 [2] 8b a5 [2] 97 a2 [2] 8b 8d }

  condition:
    any of them
}