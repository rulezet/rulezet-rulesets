rule TTP_XOR_QUAD_CurrentVersionRun_5921 {
  strings:
    $key_5921 = { 0a 4e [2] 2e 40 [2] 05 6c [2] 2b 4e [2] 3f 55 [2] 30 4f [2] 2e 52 [2] 2c 53 [2] 37 55 [2] 2b 52 [2] 37 7d }

  condition:
    any of them
}