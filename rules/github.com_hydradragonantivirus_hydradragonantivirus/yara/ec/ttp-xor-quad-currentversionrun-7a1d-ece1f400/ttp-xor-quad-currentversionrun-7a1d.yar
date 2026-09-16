rule TTP_XOR_QUAD_CurrentVersionRun_7a1d {
  strings:
    $key_7a1d = { 29 72 [2] 0d 7c [2] 26 50 [2] 08 72 [2] 1c 69 [2] 13 73 [2] 0d 6e [2] 0f 6f [2] 14 69 [2] 08 6e [2] 14 41 }

  condition:
    any of them
}