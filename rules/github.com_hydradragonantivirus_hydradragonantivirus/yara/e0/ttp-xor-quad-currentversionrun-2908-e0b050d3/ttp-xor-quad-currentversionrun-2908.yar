rule TTP_XOR_QUAD_CurrentVersionRun_2908 {
  strings:
    $key_2908 = { 7a 67 [2] 5e 69 [2] 75 45 [2] 5b 67 [2] 4f 7c [2] 40 66 [2] 5e 7b [2] 5c 7a [2] 47 7c [2] 5b 7b [2] 47 54 }

  condition:
    any of them
}