rule TTP_XOR_QUAD_CurrentVersionRun_fddd {
  strings:
    $key_fddd = { ae b2 [2] 8a bc [2] a1 90 [2] 8f b2 [2] 9b a9 [2] 94 b3 [2] 8a ae [2] 88 af [2] 93 a9 [2] 8f ae [2] 93 81 }

  condition:
    any of them
}