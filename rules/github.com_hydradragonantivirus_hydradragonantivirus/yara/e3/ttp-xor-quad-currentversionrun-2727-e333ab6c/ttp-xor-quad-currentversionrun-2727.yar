rule TTP_XOR_QUAD_CurrentVersionRun_2727 {
  strings:
    $key_2727 = { 74 48 [2] 50 46 [2] 7b 6a [2] 55 48 [2] 41 53 [2] 4e 49 [2] 50 54 [2] 52 55 [2] 49 53 [2] 55 54 [2] 49 7b }

  condition:
    any of them
}