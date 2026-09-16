rule TTP_XOR_QUAD_CurrentVersionRun_1dd1 {
  strings:
    $key_1dd1 = { 4e be [2] 6a b0 [2] 41 9c [2] 6f be [2] 7b a5 [2] 74 bf [2] 6a a2 [2] 68 a3 [2] 73 a5 [2] 6f a2 [2] 73 8d }

  condition:
    any of them
}