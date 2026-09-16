rule TTP_XOR_QUAD_CurrentVersionRun_50eb {
  strings:
    $key_50eb = { 03 84 [2] 27 8a [2] 0c a6 [2] 22 84 [2] 36 9f [2] 39 85 [2] 27 98 [2] 25 99 [2] 3e 9f [2] 22 98 [2] 3e b7 }

  condition:
    any of them
}