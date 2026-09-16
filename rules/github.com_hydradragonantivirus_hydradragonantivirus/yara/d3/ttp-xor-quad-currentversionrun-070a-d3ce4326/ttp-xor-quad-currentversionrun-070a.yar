rule TTP_XOR_QUAD_CurrentVersionRun_070a {
  strings:
    $key_070a = { 54 65 [2] 70 6b [2] 5b 47 [2] 75 65 [2] 61 7e [2] 6e 64 [2] 70 79 [2] 72 78 [2] 69 7e [2] 75 79 [2] 69 56 }

  condition:
    any of them
}