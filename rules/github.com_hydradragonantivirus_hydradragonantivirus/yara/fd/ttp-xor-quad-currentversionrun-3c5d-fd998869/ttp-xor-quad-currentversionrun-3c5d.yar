rule TTP_XOR_QUAD_CurrentVersionRun_3c5d {
  strings:
    $key_3c5d = { 6f 32 [2] 4b 3c [2] 60 10 [2] 4e 32 [2] 5a 29 [2] 55 33 [2] 4b 2e [2] 49 2f [2] 52 29 [2] 4e 2e [2] 52 01 }

  condition:
    any of them
}