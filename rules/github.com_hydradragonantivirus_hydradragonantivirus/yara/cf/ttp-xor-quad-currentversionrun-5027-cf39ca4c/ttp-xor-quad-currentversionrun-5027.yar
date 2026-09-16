rule TTP_XOR_QUAD_CurrentVersionRun_5027 {
  strings:
    $key_5027 = { 03 48 [2] 27 46 [2] 0c 6a [2] 22 48 [2] 36 53 [2] 39 49 [2] 27 54 [2] 25 55 [2] 3e 53 [2] 22 54 [2] 3e 7b }

  condition:
    any of them
}