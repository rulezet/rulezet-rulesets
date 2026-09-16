rule TTP_XOR_QUAD_CurrentVersionRun_7c11 {
  strings:
    $key_7c11 = { 2f 7e [2] 0b 70 [2] 20 5c [2] 0e 7e [2] 1a 65 [2] 15 7f [2] 0b 62 [2] 09 63 [2] 12 65 [2] 0e 62 [2] 12 4d }

  condition:
    any of them
}