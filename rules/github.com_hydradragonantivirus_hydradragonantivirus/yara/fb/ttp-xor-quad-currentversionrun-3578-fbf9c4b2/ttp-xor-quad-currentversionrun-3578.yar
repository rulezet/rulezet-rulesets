rule TTP_XOR_QUAD_CurrentVersionRun_3578 {
  strings:
    $key_3578 = { 66 17 [2] 42 19 [2] 69 35 [2] 47 17 [2] 53 0c [2] 5c 16 [2] 42 0b [2] 40 0a [2] 5b 0c [2] 47 0b [2] 5b 24 }

  condition:
    any of them
}