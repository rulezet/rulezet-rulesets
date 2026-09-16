rule TTP_XOR_QUAD_CurrentVersionRun_11d1 {
  strings:
    $key_11d1 = { 42 be [2] 66 b0 [2] 4d 9c [2] 63 be [2] 77 a5 [2] 78 bf [2] 66 a2 [2] 64 a3 [2] 7f a5 [2] 63 a2 [2] 7f 8d }

  condition:
    any of them
}