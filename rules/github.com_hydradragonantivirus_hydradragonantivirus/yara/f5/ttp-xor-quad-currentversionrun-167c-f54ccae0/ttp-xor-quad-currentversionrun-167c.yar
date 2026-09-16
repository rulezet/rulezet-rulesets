rule TTP_XOR_QUAD_CurrentVersionRun_167c {
  strings:
    $key_167c = { 45 13 [2] 61 1d [2] 4a 31 [2] 64 13 [2] 70 08 [2] 7f 12 [2] 61 0f [2] 63 0e [2] 78 08 [2] 64 0f [2] 78 20 }

  condition:
    any of them
}