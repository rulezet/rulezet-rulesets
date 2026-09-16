rule TTP_XOR_QUAD_CurrentVersionRun_450d {
  strings:
    $key_450d = { 16 62 [2] 32 6c [2] 19 40 [2] 37 62 [2] 23 79 [2] 2c 63 [2] 32 7e [2] 30 7f [2] 2b 79 [2] 37 7e [2] 2b 51 }

  condition:
    any of them
}