rule TTP_XOR_QUAD_CurrentVersionRun_0e7c {
  strings:
    $key_0e7c = { 5d 13 [2] 79 1d [2] 52 31 [2] 7c 13 [2] 68 08 [2] 67 12 [2] 79 0f [2] 7b 0e [2] 60 08 [2] 7c 0f [2] 60 20 }

  condition:
    any of them
}