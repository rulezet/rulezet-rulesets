rule TTP_XOR_QUAD_CurrentVersionRun_30f4 {
  strings:
    $key_30f4 = { 63 9b [2] 47 95 [2] 6c b9 [2] 42 9b [2] 56 80 [2] 59 9a [2] 47 87 [2] 45 86 [2] 5e 80 [2] 42 87 [2] 5e a8 }

  condition:
    any of them
}