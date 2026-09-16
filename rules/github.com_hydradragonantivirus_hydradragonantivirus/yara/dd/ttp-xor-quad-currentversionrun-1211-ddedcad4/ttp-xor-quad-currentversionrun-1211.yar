rule TTP_XOR_QUAD_CurrentVersionRun_1211 {
  strings:
    $key_1211 = { 41 7e [2] 65 70 [2] 4e 5c [2] 60 7e [2] 74 65 [2] 7b 7f [2] 65 62 [2] 67 63 [2] 7c 65 [2] 60 62 [2] 7c 4d }

  condition:
    any of them
}