rule TTP_XOR_QUAD_CurrentVersionRun_6cc1 {
  strings:
    $key_6cc1 = { 3f ae [2] 1b a0 [2] 30 8c [2] 1e ae [2] 0a b5 [2] 05 af [2] 1b b2 [2] 19 b3 [2] 02 b5 [2] 1e b2 [2] 02 9d }

  condition:
    any of them
}