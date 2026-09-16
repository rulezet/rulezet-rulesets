rule TTP_XOR_QUAD_CurrentVersionRun_ebc1 {
  strings:
    $key_ebc1 = { b8 ae [2] 9c a0 [2] b7 8c [2] 99 ae [2] 8d b5 [2] 82 af [2] 9c b2 [2] 9e b3 [2] 85 b5 [2] 99 b2 [2] 85 9d }

  condition:
    any of them
}