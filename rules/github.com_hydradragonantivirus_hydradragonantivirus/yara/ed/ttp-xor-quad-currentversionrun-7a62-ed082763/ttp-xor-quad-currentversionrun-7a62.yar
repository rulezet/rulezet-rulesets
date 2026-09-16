rule TTP_XOR_QUAD_CurrentVersionRun_7a62 {
  strings:
    $key_7a62 = { 29 0d [2] 0d 03 [2] 26 2f [2] 08 0d [2] 1c 16 [2] 13 0c [2] 0d 11 [2] 0f 10 [2] 14 16 [2] 08 11 [2] 14 3e }

  condition:
    any of them
}