rule TTP_XOR_QUAD_CurrentVersionRun_37c1 {
  strings:
    $key_37c1 = { 64 ae [2] 40 a0 [2] 6b 8c [2] 45 ae [2] 51 b5 [2] 5e af [2] 40 b2 [2] 42 b3 [2] 59 b5 [2] 45 b2 [2] 59 9d }

  condition:
    any of them
}