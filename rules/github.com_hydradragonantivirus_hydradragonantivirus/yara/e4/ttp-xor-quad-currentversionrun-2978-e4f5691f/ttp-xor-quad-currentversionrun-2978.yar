rule TTP_XOR_QUAD_CurrentVersionRun_2978 {
  strings:
    $key_2978 = { 7a 17 [2] 5e 19 [2] 75 35 [2] 5b 17 [2] 4f 0c [2] 40 16 [2] 5e 0b [2] 5c 0a [2] 47 0c [2] 5b 0b [2] 47 24 }

  condition:
    any of them
}