rule TTP_XOR_QUAD_CurrentVersionRun_453d {
  strings:
    $key_453d = { 16 52 [2] 32 5c [2] 19 70 [2] 37 52 [2] 23 49 [2] 2c 53 [2] 32 4e [2] 30 4f [2] 2b 49 [2] 37 4e [2] 2b 61 }

  condition:
    any of them
}