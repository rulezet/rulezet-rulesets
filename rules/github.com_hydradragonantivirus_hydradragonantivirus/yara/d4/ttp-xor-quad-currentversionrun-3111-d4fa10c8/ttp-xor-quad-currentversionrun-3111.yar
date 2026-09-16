rule TTP_XOR_QUAD_CurrentVersionRun_3111 {
  strings:
    $key_3111 = { 62 7e [2] 46 70 [2] 6d 5c [2] 43 7e [2] 57 65 [2] 58 7f [2] 46 62 [2] 44 63 [2] 5f 65 [2] 43 62 [2] 5f 4d }

  condition:
    any of them
}