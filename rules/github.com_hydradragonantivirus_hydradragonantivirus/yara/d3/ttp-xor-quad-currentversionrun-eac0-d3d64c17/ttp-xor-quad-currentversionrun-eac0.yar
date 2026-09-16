rule TTP_XOR_QUAD_CurrentVersionRun_eac0 {
  strings:
    $key_eac0 = { b9 af [2] 9d a1 [2] b6 8d [2] 98 af [2] 8c b4 [2] 83 ae [2] 9d b3 [2] 9f b2 [2] 84 b4 [2] 98 b3 [2] 84 9c }

  condition:
    any of them
}