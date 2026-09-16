rule TTP_XOR_QUAD_CurrentVersionRun_5ddd {
  strings:
    $key_5ddd = { 0e b2 [2] 2a bc [2] 01 90 [2] 2f b2 [2] 3b a9 [2] 34 b3 [2] 2a ae [2] 28 af [2] 33 a9 [2] 2f ae [2] 33 81 }

  condition:
    any of them
}