rule TTP_XOR_QUAD_CurrentVersionRun_0941 {
  strings:
    $key_0941 = { 5a 2e [2] 7e 20 [2] 55 0c [2] 7b 2e [2] 6f 35 [2] 60 2f [2] 7e 32 [2] 7c 33 [2] 67 35 [2] 7b 32 [2] 67 1d }

  condition:
    any of them
}