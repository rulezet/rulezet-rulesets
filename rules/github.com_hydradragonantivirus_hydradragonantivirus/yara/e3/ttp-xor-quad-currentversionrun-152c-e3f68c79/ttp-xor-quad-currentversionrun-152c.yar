rule TTP_XOR_QUAD_CurrentVersionRun_152c {
  strings:
    $key_152c = { 46 43 [2] 62 4d [2] 49 61 [2] 67 43 [2] 73 58 [2] 7c 42 [2] 62 5f [2] 60 5e [2] 7b 58 [2] 67 5f [2] 7b 70 }

  condition:
    any of them
}