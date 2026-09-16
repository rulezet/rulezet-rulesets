rule TTP_XOR_QUAD_CurrentVersionRun_3ad1 {
  strings:
    $key_3ad1 = { 69 be [2] 4d b0 [2] 66 9c [2] 48 be [2] 5c a5 [2] 53 bf [2] 4d a2 [2] 4f a3 [2] 54 a5 [2] 48 a2 [2] 54 8d }

  condition:
    any of them
}