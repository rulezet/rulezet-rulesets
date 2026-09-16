rule TTP_XOR_QUAD_CurrentVersionRun_3515 {
  strings:
    $key_3515 = { 66 7a [2] 42 74 [2] 69 58 [2] 47 7a [2] 53 61 [2] 5c 7b [2] 42 66 [2] 40 67 [2] 5b 61 [2] 47 66 [2] 5b 49 }

  condition:
    any of them
}