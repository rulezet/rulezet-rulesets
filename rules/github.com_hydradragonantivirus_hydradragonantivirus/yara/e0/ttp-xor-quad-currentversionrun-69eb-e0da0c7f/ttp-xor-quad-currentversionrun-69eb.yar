rule TTP_XOR_QUAD_CurrentVersionRun_69eb {
  strings:
    $key_69eb = { 3a 84 [2] 1e 8a [2] 35 a6 [2] 1b 84 [2] 0f 9f [2] 00 85 [2] 1e 98 [2] 1c 99 [2] 07 9f [2] 1b 98 [2] 07 b7 }

  condition:
    any of them
}