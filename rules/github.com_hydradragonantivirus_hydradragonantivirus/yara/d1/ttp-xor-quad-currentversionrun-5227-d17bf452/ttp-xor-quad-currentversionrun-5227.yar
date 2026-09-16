rule TTP_XOR_QUAD_CurrentVersionRun_5227 {
  strings:
    $key_5227 = { 01 48 [2] 25 46 [2] 0e 6a [2] 20 48 [2] 34 53 [2] 3b 49 [2] 25 54 [2] 27 55 [2] 3c 53 [2] 20 54 [2] 3c 7b }

  condition:
    any of them
}