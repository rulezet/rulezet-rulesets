rule TTP_XOR_QUAD_CurrentVersionRun_197b {
  strings:
    $key_197b = { 4a 14 [2] 6e 1a [2] 45 36 [2] 6b 14 [2] 7f 0f [2] 70 15 [2] 6e 08 [2] 6c 09 [2] 77 0f [2] 6b 08 [2] 77 27 }

  condition:
    any of them
}