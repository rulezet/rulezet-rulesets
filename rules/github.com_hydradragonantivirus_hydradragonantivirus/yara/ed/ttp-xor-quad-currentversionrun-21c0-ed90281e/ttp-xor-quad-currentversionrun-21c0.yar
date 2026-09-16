rule TTP_XOR_QUAD_CurrentVersionRun_21c0 {
  strings:
    $key_21c0 = { 72 af [2] 56 a1 [2] 7d 8d [2] 53 af [2] 47 b4 [2] 48 ae [2] 56 b3 [2] 54 b2 [2] 4f b4 [2] 53 b3 [2] 4f 9c }

  condition:
    any of them
}