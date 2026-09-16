rule TTP_XOR_QUAD_CurrentVersionRun_e9c0 {
  strings:
    $key_e9c0 = { ba af [2] 9e a1 [2] b5 8d [2] 9b af [2] 8f b4 [2] 80 ae [2] 9e b3 [2] 9c b2 [2] 87 b4 [2] 9b b3 [2] 87 9c }

  condition:
    any of them
}