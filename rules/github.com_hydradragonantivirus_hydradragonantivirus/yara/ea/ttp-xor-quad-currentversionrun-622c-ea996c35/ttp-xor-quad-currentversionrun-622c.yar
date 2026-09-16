rule TTP_XOR_QUAD_CurrentVersionRun_622c {
  strings:
    $key_622c = { 31 43 [2] 15 4d [2] 3e 61 [2] 10 43 [2] 04 58 [2] 0b 42 [2] 15 5f [2] 17 5e [2] 0c 58 [2] 10 5f [2] 0c 70 }

  condition:
    any of them
}