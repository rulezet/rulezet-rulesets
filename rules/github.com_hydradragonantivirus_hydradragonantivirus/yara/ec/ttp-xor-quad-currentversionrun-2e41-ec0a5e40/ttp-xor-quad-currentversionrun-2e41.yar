rule TTP_XOR_QUAD_CurrentVersionRun_2e41 {
  strings:
    $key_2e41 = { 7d 2e [2] 59 20 [2] 72 0c [2] 5c 2e [2] 48 35 [2] 47 2f [2] 59 32 [2] 5b 33 [2] 40 35 [2] 5c 32 [2] 40 1d }

  condition:
    any of them
}