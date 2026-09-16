rule TTP_XOR_QUAD_CurrentVersionRun_4ceb {
  strings:
    $key_4ceb = { 1f 84 [2] 3b 8a [2] 10 a6 [2] 3e 84 [2] 2a 9f [2] 25 85 [2] 3b 98 [2] 39 99 [2] 22 9f [2] 3e 98 [2] 22 b7 }

  condition:
    any of them
}