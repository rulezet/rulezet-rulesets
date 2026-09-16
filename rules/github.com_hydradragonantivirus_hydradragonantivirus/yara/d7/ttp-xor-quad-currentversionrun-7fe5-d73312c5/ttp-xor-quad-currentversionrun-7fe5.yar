rule TTP_XOR_QUAD_CurrentVersionRun_7fe5 {
  strings:
    $key_7fe5 = { 2c 8a [2] 08 84 [2] 23 a8 [2] 0d 8a [2] 19 91 [2] 16 8b [2] 08 96 [2] 0a 97 [2] 11 91 [2] 0d 96 [2] 11 b9 }

  condition:
    any of them
}