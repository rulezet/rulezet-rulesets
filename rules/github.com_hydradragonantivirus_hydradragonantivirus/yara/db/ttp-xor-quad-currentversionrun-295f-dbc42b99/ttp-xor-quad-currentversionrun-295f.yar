rule TTP_XOR_QUAD_CurrentVersionRun_295f {
  strings:
    $key_295f = { 7a 30 [2] 5e 3e [2] 75 12 [2] 5b 30 [2] 4f 2b [2] 40 31 [2] 5e 2c [2] 5c 2d [2] 47 2b [2] 5b 2c [2] 47 03 }

  condition:
    any of them
}