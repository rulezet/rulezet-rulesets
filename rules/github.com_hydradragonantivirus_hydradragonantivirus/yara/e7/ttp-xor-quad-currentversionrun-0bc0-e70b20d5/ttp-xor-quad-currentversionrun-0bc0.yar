rule TTP_XOR_QUAD_CurrentVersionRun_0bc0 {
  strings:
    $key_0bc0 = { 58 af [2] 7c a1 [2] 57 8d [2] 79 af [2] 6d b4 [2] 62 ae [2] 7c b3 [2] 7e b2 [2] 65 b4 [2] 79 b3 [2] 65 9c }

  condition:
    any of them
}