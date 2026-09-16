rule TTP_XOR_QUAD_CurrentVersionRun_7dc0 {
  strings:
    $key_7dc0 = { 2e af [2] 0a a1 [2] 21 8d [2] 0f af [2] 1b b4 [2] 14 ae [2] 0a b3 [2] 08 b2 [2] 13 b4 [2] 0f b3 [2] 13 9c }

  condition:
    any of them
}