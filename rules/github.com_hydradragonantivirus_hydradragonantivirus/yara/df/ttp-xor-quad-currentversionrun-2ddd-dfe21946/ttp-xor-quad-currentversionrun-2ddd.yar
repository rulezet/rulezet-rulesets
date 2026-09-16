rule TTP_XOR_QUAD_CurrentVersionRun_2ddd {
  strings:
    $key_2ddd = { 7e b2 [2] 5a bc [2] 71 90 [2] 5f b2 [2] 4b a9 [2] 44 b3 [2] 5a ae [2] 58 af [2] 43 a9 [2] 5f ae [2] 43 81 }

  condition:
    any of them
}