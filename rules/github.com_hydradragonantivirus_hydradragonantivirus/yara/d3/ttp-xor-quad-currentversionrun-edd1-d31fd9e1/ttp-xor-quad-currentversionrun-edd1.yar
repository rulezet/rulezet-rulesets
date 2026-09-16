rule TTP_XOR_QUAD_CurrentVersionRun_edd1 {
  strings:
    $key_edd1 = { be be [2] 9a b0 [2] b1 9c [2] 9f be [2] 8b a5 [2] 84 bf [2] 9a a2 [2] 98 a3 [2] 83 a5 [2] 9f a2 [2] 83 8d }

  condition:
    any of them
}