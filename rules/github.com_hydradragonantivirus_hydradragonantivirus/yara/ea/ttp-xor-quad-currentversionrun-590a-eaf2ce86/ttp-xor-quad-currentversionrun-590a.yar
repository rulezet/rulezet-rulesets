rule TTP_XOR_QUAD_CurrentVersionRun_590a {
  strings:
    $key_590a = { 0a 65 [2] 2e 6b [2] 05 47 [2] 2b 65 [2] 3f 7e [2] 30 64 [2] 2e 79 [2] 2c 78 [2] 37 7e [2] 2b 79 [2] 37 56 }

  condition:
    any of them
}