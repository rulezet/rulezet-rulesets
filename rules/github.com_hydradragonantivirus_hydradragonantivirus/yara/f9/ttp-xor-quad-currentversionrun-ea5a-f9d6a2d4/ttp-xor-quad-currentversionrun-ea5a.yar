rule TTP_XOR_QUAD_CurrentVersionRun_ea5a {
  strings:
    $key_ea5a = { b9 35 [2] 9d 3b [2] b6 17 [2] 98 35 [2] 8c 2e [2] 83 34 [2] 9d 29 [2] 9f 28 [2] 84 2e [2] 98 29 [2] 84 06 }

  condition:
    any of them
}