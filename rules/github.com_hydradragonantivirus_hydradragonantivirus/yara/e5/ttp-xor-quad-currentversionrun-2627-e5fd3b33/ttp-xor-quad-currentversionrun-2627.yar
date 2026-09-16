rule TTP_XOR_QUAD_CurrentVersionRun_2627 {
  strings:
    $key_2627 = { 75 48 [2] 51 46 [2] 7a 6a [2] 54 48 [2] 40 53 [2] 4f 49 [2] 51 54 [2] 53 55 [2] 48 53 [2] 54 54 [2] 48 7b }

  condition:
    any of them
}