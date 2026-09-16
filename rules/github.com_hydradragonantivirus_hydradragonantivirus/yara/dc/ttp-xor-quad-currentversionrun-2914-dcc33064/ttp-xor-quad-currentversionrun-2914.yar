rule TTP_XOR_QUAD_CurrentVersionRun_2914 {
  strings:
    $key_2914 = { 7a 7b [2] 5e 75 [2] 75 59 [2] 5b 7b [2] 4f 60 [2] 40 7a [2] 5e 67 [2] 5c 66 [2] 47 60 [2] 5b 67 [2] 47 48 }

  condition:
    any of them
}