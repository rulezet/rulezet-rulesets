rule TTP_XOR_QUAD_CurrentVersionRun_4062 {
  strings:
    $key_4062 = { 13 0d [2] 37 03 [2] 1c 2f [2] 32 0d [2] 26 16 [2] 29 0c [2] 37 11 [2] 35 10 [2] 2e 16 [2] 32 11 [2] 2e 3e }

  condition:
    any of them
}