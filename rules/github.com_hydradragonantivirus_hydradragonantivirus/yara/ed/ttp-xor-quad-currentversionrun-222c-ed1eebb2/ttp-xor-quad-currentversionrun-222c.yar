rule TTP_XOR_QUAD_CurrentVersionRun_222c {
  strings:
    $key_222c = { 71 43 [2] 55 4d [2] 7e 61 [2] 50 43 [2] 44 58 [2] 4b 42 [2] 55 5f [2] 57 5e [2] 4c 58 [2] 50 5f [2] 4c 70 }

  condition:
    any of them
}