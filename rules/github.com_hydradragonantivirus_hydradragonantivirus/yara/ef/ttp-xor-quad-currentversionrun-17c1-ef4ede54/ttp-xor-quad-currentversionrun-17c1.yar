rule TTP_XOR_QUAD_CurrentVersionRun_17c1 {
  strings:
    $key_17c1 = { 44 ae [2] 60 a0 [2] 4b 8c [2] 65 ae [2] 71 b5 [2] 7e af [2] 60 b2 [2] 62 b3 [2] 79 b5 [2] 65 b2 [2] 79 9d }

  condition:
    any of them
}