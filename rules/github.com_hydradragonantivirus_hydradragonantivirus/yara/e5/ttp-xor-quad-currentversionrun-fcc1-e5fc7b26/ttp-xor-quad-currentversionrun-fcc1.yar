rule TTP_XOR_QUAD_CurrentVersionRun_fcc1 {
  strings:
    $key_fcc1 = { af ae [2] 8b a0 [2] a0 8c [2] 8e ae [2] 9a b5 [2] 95 af [2] 8b b2 [2] 89 b3 [2] 92 b5 [2] 8e b2 [2] 92 9d }

  condition:
    any of them
}