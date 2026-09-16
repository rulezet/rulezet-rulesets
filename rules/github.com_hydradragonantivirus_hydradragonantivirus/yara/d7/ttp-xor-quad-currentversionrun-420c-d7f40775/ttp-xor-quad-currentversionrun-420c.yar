rule TTP_XOR_QUAD_CurrentVersionRun_420c {
  strings:
    $key_420c = { 11 63 [2] 35 6d [2] 1e 41 [2] 30 63 [2] 24 78 [2] 2b 62 [2] 35 7f [2] 37 7e [2] 2c 78 [2] 30 7f [2] 2c 50 }

  condition:
    any of them
}