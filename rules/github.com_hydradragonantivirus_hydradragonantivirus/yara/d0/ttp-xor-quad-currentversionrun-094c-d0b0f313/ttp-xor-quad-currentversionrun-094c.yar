rule TTP_XOR_QUAD_CurrentVersionRun_094c {
  strings:
    $key_094c = { 5a 23 [2] 7e 2d [2] 55 01 [2] 7b 23 [2] 6f 38 [2] 60 22 [2] 7e 3f [2] 7c 3e [2] 67 38 [2] 7b 3f [2] 67 10 }

  condition:
    any of them
}