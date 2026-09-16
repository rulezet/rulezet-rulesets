rule TTP_XOR_QUAD_CurrentVersionRun_d8d1 {
  strings:
    $key_d8d1 = { 8b be [2] af b0 [2] 84 9c [2] aa be [2] be a5 [2] b1 bf [2] af a2 [2] ad a3 [2] b6 a5 [2] aa a2 [2] b6 8d }

  condition:
    any of them
}