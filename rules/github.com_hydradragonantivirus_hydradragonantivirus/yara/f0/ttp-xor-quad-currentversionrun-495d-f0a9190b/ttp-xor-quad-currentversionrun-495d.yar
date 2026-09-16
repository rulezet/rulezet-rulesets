rule TTP_XOR_QUAD_CurrentVersionRun_495d {
  strings:
    $key_495d = { 1a 32 [2] 3e 3c [2] 15 10 [2] 3b 32 [2] 2f 29 [2] 20 33 [2] 3e 2e [2] 3c 2f [2] 27 29 [2] 3b 2e [2] 27 01 }

  condition:
    any of them
}