rule TTP_XOR_QUAD_CurrentVersionRun_38c1 {
  strings:
    $key_38c1 = { 6b ae [2] 4f a0 [2] 64 8c [2] 4a ae [2] 5e b5 [2] 51 af [2] 4f b2 [2] 4d b3 [2] 56 b5 [2] 4a b2 [2] 56 9d }

  condition:
    any of them
}