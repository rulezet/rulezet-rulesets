rule TTP_XOR_QUAD_CurrentVersionRun_590c {
  strings:
    $key_590c = { 0a 63 [2] 2e 6d [2] 05 41 [2] 2b 63 [2] 3f 78 [2] 30 62 [2] 2e 7f [2] 2c 7e [2] 37 78 [2] 2b 7f [2] 37 50 }

  condition:
    any of them
}