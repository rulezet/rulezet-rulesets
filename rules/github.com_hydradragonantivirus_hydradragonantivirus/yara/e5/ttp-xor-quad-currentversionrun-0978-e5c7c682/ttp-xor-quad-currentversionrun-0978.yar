rule TTP_XOR_QUAD_CurrentVersionRun_0978 {
  strings:
    $key_0978 = { 5a 17 [2] 7e 19 [2] 55 35 [2] 7b 17 [2] 6f 0c [2] 60 16 [2] 7e 0b [2] 7c 0a [2] 67 0c [2] 7b 0b [2] 67 24 }

  condition:
    any of them
}