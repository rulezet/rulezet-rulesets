rule TTP_XOR_QUAD_CurrentVersionRun_ebd1 {
  strings:
    $key_ebd1 = { b8 be [2] 9c b0 [2] b7 9c [2] 99 be [2] 8d a5 [2] 82 bf [2] 9c a2 [2] 9e a3 [2] 85 a5 [2] 99 a2 [2] 85 8d }

  condition:
    any of them
}