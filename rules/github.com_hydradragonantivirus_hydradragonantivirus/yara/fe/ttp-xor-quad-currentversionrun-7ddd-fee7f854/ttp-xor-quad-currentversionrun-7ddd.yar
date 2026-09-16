rule TTP_XOR_QUAD_CurrentVersionRun_7ddd {
  strings:
    $key_7ddd = { 2e b2 [2] 0a bc [2] 21 90 [2] 0f b2 [2] 1b a9 [2] 14 b3 [2] 0a ae [2] 08 af [2] 13 a9 [2] 0f ae [2] 13 81 }

  condition:
    any of them
}