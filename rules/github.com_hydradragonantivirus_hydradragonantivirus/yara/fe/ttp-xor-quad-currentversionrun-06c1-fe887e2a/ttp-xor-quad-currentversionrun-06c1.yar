rule TTP_XOR_QUAD_CurrentVersionRun_06c1 {
  strings:
    $key_06c1 = { 55 ae [2] 71 a0 [2] 5a 8c [2] 74 ae [2] 60 b5 [2] 6f af [2] 71 b2 [2] 73 b3 [2] 68 b5 [2] 74 b2 [2] 68 9d }

  condition:
    any of them
}