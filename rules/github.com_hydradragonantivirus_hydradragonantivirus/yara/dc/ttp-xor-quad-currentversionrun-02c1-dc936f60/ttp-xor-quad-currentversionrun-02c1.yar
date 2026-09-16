rule TTP_XOR_QUAD_CurrentVersionRun_02c1 {
  strings:
    $key_02c1 = { 51 ae [2] 75 a0 [2] 5e 8c [2] 70 ae [2] 64 b5 [2] 6b af [2] 75 b2 [2] 77 b3 [2] 6c b5 [2] 70 b2 [2] 6c 9d }

  condition:
    any of them
}