rule TTP_XOR_QUAD_CurrentVersionRun_32c1 {
  strings:
    $key_32c1 = { 61 ae [2] 45 a0 [2] 6e 8c [2] 40 ae [2] 54 b5 [2] 5b af [2] 45 b2 [2] 47 b3 [2] 5c b5 [2] 40 b2 [2] 5c 9d }

  condition:
    any of them
}