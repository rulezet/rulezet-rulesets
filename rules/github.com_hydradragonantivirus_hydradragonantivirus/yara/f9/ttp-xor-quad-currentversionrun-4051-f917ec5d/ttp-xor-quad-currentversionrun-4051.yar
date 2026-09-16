rule TTP_XOR_QUAD_CurrentVersionRun_4051 {
  strings:
    $key_4051 = { 13 3e [2] 37 30 [2] 1c 1c [2] 32 3e [2] 26 25 [2] 29 3f [2] 37 22 [2] 35 23 [2] 2e 25 [2] 32 22 [2] 2e 0d }

  condition:
    any of them
}