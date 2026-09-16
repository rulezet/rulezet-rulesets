rule TTP_XOR_QUAD_CurrentVersionRun_30f9 {
  strings:
    $key_30f9 = { 63 96 [2] 47 98 [2] 6c b4 [2] 42 96 [2] 56 8d [2] 59 97 [2] 47 8a [2] 45 8b [2] 5e 8d [2] 42 8a [2] 5e a5 }

  condition:
    any of them
}