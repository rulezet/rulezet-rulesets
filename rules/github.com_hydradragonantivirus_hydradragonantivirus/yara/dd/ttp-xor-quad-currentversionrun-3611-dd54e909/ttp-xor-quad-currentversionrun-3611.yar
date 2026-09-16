rule TTP_XOR_QUAD_CurrentVersionRun_3611 {
  strings:
    $key_3611 = { 65 7e [2] 41 70 [2] 6a 5c [2] 44 7e [2] 50 65 [2] 5f 7f [2] 41 62 [2] 43 63 [2] 58 65 [2] 44 62 [2] 58 4d }

  condition:
    any of them
}