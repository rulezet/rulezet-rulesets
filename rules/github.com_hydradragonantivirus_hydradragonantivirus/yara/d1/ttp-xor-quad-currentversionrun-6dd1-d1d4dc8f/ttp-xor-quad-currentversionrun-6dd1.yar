rule TTP_XOR_QUAD_CurrentVersionRun_6dd1 {
  strings:
    $key_6dd1 = { 3e be [2] 1a b0 [2] 31 9c [2] 1f be [2] 0b a5 [2] 04 bf [2] 1a a2 [2] 18 a3 [2] 03 a5 [2] 1f a2 [2] 03 8d }

  condition:
    any of them
}