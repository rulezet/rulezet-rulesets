rule TTP_XOR_QUAD_CurrentVersionRun_4629 {
  strings:
    $key_4629 = { 15 46 [2] 31 48 [2] 1a 64 [2] 34 46 [2] 20 5d [2] 2f 47 [2] 31 5a [2] 33 5b [2] 28 5d [2] 34 5a [2] 28 75 }

  condition:
    any of them
}