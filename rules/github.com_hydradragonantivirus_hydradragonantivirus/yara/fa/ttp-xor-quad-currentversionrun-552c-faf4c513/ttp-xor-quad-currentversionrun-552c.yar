rule TTP_XOR_QUAD_CurrentVersionRun_552c {
  strings:
    $key_552c = { 06 43 [2] 22 4d [2] 09 61 [2] 27 43 [2] 33 58 [2] 3c 42 [2] 22 5f [2] 20 5e [2] 3b 58 [2] 27 5f [2] 3b 70 }

  condition:
    any of them
}