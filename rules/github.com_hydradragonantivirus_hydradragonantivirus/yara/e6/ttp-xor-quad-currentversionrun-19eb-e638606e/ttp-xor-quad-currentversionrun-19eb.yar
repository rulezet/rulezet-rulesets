rule TTP_XOR_QUAD_CurrentVersionRun_19eb {
  strings:
    $key_19eb = { 4a 84 [2] 6e 8a [2] 45 a6 [2] 6b 84 [2] 7f 9f [2] 70 85 [2] 6e 98 [2] 6c 99 [2] 77 9f [2] 6b 98 [2] 77 b7 }

  condition:
    any of them
}