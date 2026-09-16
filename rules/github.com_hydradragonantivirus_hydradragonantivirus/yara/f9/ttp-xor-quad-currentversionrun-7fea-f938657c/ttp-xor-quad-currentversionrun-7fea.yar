rule TTP_XOR_QUAD_CurrentVersionRun_7fea {
  strings:
    $key_7fea = { 2c 85 [2] 08 8b [2] 23 a7 [2] 0d 85 [2] 19 9e [2] 16 84 [2] 08 99 [2] 0a 98 [2] 11 9e [2] 0d 99 [2] 11 b6 }

  condition:
    any of them
}