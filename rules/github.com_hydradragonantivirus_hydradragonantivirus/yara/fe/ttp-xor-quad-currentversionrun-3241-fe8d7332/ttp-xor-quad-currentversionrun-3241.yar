rule TTP_XOR_QUAD_CurrentVersionRun_3241 {
  strings:
    $key_3241 = { 61 2e [2] 45 20 [2] 6e 0c [2] 40 2e [2] 54 35 [2] 5b 2f [2] 45 32 [2] 47 33 [2] 5c 35 [2] 40 32 [2] 5c 1d }

  condition:
    any of them
}