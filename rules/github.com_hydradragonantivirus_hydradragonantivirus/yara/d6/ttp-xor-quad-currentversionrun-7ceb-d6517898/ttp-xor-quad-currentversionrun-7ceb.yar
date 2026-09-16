rule TTP_XOR_QUAD_CurrentVersionRun_7ceb {
  strings:
    $key_7ceb = { 2f 84 [2] 0b 8a [2] 20 a6 [2] 0e 84 [2] 1a 9f [2] 15 85 [2] 0b 98 [2] 09 99 [2] 12 9f [2] 0e 98 [2] 12 b7 }

  condition:
    any of them
}