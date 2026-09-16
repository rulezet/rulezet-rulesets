rule TTP_XOR_QUAD_CurrentVersionRun_30c0 {
  strings:
    $key_30c0 = { 63 af [2] 47 a1 [2] 6c 8d [2] 42 af [2] 56 b4 [2] 59 ae [2] 47 b3 [2] 45 b2 [2] 5e b4 [2] 42 b3 [2] 5e 9c }

  condition:
    any of them
}