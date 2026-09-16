rule TTP_XOR_QUAD_CurrentVersionRun_620d {
  strings:
    $key_620d = { 31 62 [2] 15 6c [2] 3e 40 [2] 10 62 [2] 04 79 [2] 0b 63 [2] 15 7e [2] 17 7f [2] 0c 79 [2] 10 7e [2] 0c 51 }

  condition:
    any of them
}