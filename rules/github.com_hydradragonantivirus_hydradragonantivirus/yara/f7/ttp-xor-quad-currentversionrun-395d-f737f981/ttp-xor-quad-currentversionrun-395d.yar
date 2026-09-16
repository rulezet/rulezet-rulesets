rule TTP_XOR_QUAD_CurrentVersionRun_395d {
  strings:
    $key_395d = { 6a 32 [2] 4e 3c [2] 65 10 [2] 4b 32 [2] 5f 29 [2] 50 33 [2] 4e 2e [2] 4c 2f [2] 57 29 [2] 4b 2e [2] 57 01 }

  condition:
    any of them
}