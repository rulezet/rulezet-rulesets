rule TTP_XOR_QUAD_CurrentVersionRun_3b41 {
  strings:
    $key_3b41 = { 68 2e [2] 4c 20 [2] 67 0c [2] 49 2e [2] 5d 35 [2] 52 2f [2] 4c 32 [2] 4e 33 [2] 55 35 [2] 49 32 [2] 55 1d }

  condition:
    any of them
}