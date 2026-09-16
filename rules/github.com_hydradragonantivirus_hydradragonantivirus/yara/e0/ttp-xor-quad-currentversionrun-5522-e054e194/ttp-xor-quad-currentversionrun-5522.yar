rule TTP_XOR_QUAD_CurrentVersionRun_5522 {
  strings:
    $key_5522 = { 06 4d [2] 22 43 [2] 09 6f [2] 27 4d [2] 33 56 [2] 3c 4c [2] 22 51 [2] 20 50 [2] 3b 56 [2] 27 51 [2] 3b 7e }

  condition:
    any of them
}