rule TTP_XOR_QUAD_CurrentVersionRun_20eb {
  strings:
    $key_20eb = { 73 84 [2] 57 8a [2] 7c a6 [2] 52 84 [2] 46 9f [2] 49 85 [2] 57 98 [2] 55 99 [2] 4e 9f [2] 52 98 [2] 4e b7 }

  condition:
    any of them
}