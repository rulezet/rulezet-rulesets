rule TTP_XOR_QUAD_CurrentVersionRun_19c0 {
  strings:
    $key_19c0 = { 4a af [2] 6e a1 [2] 45 8d [2] 6b af [2] 7f b4 [2] 70 ae [2] 6e b3 [2] 6c b2 [2] 77 b4 [2] 6b b3 [2] 77 9c }

  condition:
    any of them
}