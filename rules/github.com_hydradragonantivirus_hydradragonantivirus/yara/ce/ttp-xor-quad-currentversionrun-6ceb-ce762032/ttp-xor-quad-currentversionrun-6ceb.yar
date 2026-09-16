rule TTP_XOR_QUAD_CurrentVersionRun_6ceb {
  strings:
    $key_6ceb = { 3f 84 [2] 1b 8a [2] 30 a6 [2] 1e 84 [2] 0a 9f [2] 05 85 [2] 1b 98 [2] 19 99 [2] 02 9f [2] 1e 98 [2] 02 b7 }

  condition:
    any of them
}