rule TTP_XOR_QUAD_CurrentVersionRun_7deb {
  strings:
    $key_7deb = { 2e 84 [2] 0a 8a [2] 21 a6 [2] 0f 84 [2] 1b 9f [2] 14 85 [2] 0a 98 [2] 08 99 [2] 13 9f [2] 0f 98 [2] 13 b7 }

  condition:
    any of them
}