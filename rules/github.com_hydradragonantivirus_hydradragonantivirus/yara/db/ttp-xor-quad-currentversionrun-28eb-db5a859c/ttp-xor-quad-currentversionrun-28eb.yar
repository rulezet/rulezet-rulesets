rule TTP_XOR_QUAD_CurrentVersionRun_28eb {
  strings:
    $key_28eb = { 7b 84 [2] 5f 8a [2] 74 a6 [2] 5a 84 [2] 4e 9f [2] 41 85 [2] 5f 98 [2] 5d 99 [2] 46 9f [2] 5a 98 [2] 46 b7 }

  condition:
    any of them
}