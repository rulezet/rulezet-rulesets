rule TTP_XOR_QUAD_CurrentVersionRun_eac1 {
  strings:
    $key_eac1 = { b9 ae [2] 9d a0 [2] b6 8c [2] 98 ae [2] 8c b5 [2] 83 af [2] 9d b2 [2] 9f b3 [2] 84 b5 [2] 98 b2 [2] 84 9d }

  condition:
    any of them
}