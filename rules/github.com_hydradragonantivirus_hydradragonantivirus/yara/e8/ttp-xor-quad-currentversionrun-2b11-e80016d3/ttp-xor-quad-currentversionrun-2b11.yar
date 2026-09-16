rule TTP_XOR_QUAD_CurrentVersionRun_2b11 {
  strings:
    $key_2b11 = { 78 7e [2] 5c 70 [2] 77 5c [2] 59 7e [2] 4d 65 [2] 42 7f [2] 5c 62 [2] 5e 63 [2] 45 65 [2] 59 62 [2] 45 4d }

  condition:
    any of them
}