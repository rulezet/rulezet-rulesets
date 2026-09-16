rule TTP_XOR_QUAD_CurrentVersionRun_7ffb {
  strings:
    $key_7ffb = { 2c 94 [2] 08 9a [2] 23 b6 [2] 0d 94 [2] 19 8f [2] 16 95 [2] 08 88 [2] 0a 89 [2] 11 8f [2] 0d 88 [2] 11 a7 }

  condition:
    any of them
}