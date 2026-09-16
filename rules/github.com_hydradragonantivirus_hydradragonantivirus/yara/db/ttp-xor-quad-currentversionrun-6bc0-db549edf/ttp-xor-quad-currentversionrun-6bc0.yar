rule TTP_XOR_QUAD_CurrentVersionRun_6bc0 {
  strings:
    $key_6bc0 = { 38 af [2] 1c a1 [2] 37 8d [2] 19 af [2] 0d b4 [2] 02 ae [2] 1c b3 [2] 1e b2 [2] 05 b4 [2] 19 b3 [2] 05 9c }

  condition:
    any of them
}