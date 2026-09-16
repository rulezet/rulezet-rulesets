rule TTP_XOR_QUAD_CurrentVersionRun_1901 {
  strings:
    $key_1901 = { 4a 6e [2] 6e 60 [2] 45 4c [2] 6b 6e [2] 7f 75 [2] 70 6f [2] 6e 72 [2] 6c 73 [2] 77 75 [2] 6b 72 [2] 77 5d }

  condition:
    any of them
}