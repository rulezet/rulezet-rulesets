rule TTP_XOR_QUAD_CurrentVersionRun_1511 {
  strings:
    $key_1511 = { 46 7e [2] 62 70 [2] 49 5c [2] 67 7e [2] 73 65 [2] 7c 7f [2] 62 62 [2] 60 63 [2] 7b 65 [2] 67 62 [2] 7b 4d }

  condition:
    any of them
}