rule TTP_XOR_QUAD_CurrentVersionRun_597f {
  strings:
    $key_597f = { 0a 10 [2] 2e 1e [2] 05 32 [2] 2b 10 [2] 3f 0b [2] 30 11 [2] 2e 0c [2] 2c 0d [2] 37 0b [2] 2b 0c [2] 37 23 }

  condition:
    any of them
}