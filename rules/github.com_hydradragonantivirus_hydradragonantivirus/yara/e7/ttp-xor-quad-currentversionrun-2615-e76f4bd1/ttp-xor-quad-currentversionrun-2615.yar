rule TTP_XOR_QUAD_CurrentVersionRun_2615 {
  strings:
    $key_2615 = { 75 7a [2] 51 74 [2] 7a 58 [2] 54 7a [2] 40 61 [2] 4f 7b [2] 51 66 [2] 53 67 [2] 48 61 [2] 54 66 [2] 48 49 }

  condition:
    any of them
}