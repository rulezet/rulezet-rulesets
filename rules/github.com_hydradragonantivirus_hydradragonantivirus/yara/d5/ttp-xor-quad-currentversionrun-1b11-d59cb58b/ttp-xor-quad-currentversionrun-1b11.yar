rule TTP_XOR_QUAD_CurrentVersionRun_1b11 {
  strings:
    $key_1b11 = { 48 7e [2] 6c 70 [2] 47 5c [2] 69 7e [2] 7d 65 [2] 72 7f [2] 6c 62 [2] 6e 63 [2] 75 65 [2] 69 62 [2] 75 4d }

  condition:
    any of them
}