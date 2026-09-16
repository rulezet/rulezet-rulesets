rule TTP_XOR_QUAD_CurrentVersionRun_3079 {
  strings:
    $key_3079 = { 63 16 [2] 47 18 [2] 6c 34 [2] 42 16 [2] 56 0d [2] 59 17 [2] 47 0a [2] 45 0b [2] 5e 0d [2] 42 0a [2] 5e 25 }

  condition:
    any of them
}