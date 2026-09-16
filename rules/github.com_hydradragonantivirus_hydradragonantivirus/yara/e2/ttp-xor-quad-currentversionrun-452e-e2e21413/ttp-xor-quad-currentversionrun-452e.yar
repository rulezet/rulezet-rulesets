rule TTP_XOR_QUAD_CurrentVersionRun_452e {
  strings:
    $key_452e = { 16 41 [2] 32 4f [2] 19 63 [2] 37 41 [2] 23 5a [2] 2c 40 [2] 32 5d [2] 30 5c [2] 2b 5a [2] 37 5d [2] 2b 72 }

  condition:
    any of them
}