rule TTP_XOR_QUAD_CurrentVersionRun_325f {
  strings:
    $key_325f = { 61 30 [2] 45 3e [2] 6e 12 [2] 40 30 [2] 54 2b [2] 5b 31 [2] 45 2c [2] 47 2d [2] 5c 2b [2] 40 2c [2] 5c 03 }

  condition:
    any of them
}