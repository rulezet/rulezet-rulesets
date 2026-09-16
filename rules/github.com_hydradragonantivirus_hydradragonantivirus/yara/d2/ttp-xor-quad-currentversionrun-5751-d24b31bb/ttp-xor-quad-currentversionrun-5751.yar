rule TTP_XOR_QUAD_CurrentVersionRun_5751 {
  strings:
    $key_5751 = { 04 3e [2] 20 30 [2] 0b 1c [2] 25 3e [2] 31 25 [2] 3e 3f [2] 20 22 [2] 22 23 [2] 39 25 [2] 25 22 [2] 39 0d }

  condition:
    any of them
}