rule TTP_XOR_QUAD_CurrentVersionRun_3c7b {
  strings:
    $key_3c7b = { 6f 14 [2] 4b 1a [2] 60 36 [2] 4e 14 [2] 5a 0f [2] 55 15 [2] 4b 08 [2] 49 09 [2] 52 0f [2] 4e 08 [2] 52 27 }

  condition:
    any of them
}