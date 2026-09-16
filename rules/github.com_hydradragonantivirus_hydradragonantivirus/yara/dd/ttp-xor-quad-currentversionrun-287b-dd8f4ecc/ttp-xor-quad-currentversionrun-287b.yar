rule TTP_XOR_QUAD_CurrentVersionRun_287b {
  strings:
    $key_287b = { 7b 14 [2] 5f 1a [2] 74 36 [2] 5a 14 [2] 4e 0f [2] 41 15 [2] 5f 08 [2] 5d 09 [2] 46 0f [2] 5a 08 [2] 46 27 }

  condition:
    any of them
}