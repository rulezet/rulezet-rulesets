rule TTP_XOR_QUAD_CurrentVersionRun_0956 {
  strings:
    $key_0956 = { 5a 39 [2] 7e 37 [2] 55 1b [2] 7b 39 [2] 6f 22 [2] 60 38 [2] 7e 25 [2] 7c 24 [2] 67 22 [2] 7b 25 [2] 67 0a }

  condition:
    any of them
}