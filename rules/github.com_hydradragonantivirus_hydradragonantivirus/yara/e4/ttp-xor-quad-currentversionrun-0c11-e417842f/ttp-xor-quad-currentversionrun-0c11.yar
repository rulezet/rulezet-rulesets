rule TTP_XOR_QUAD_CurrentVersionRun_0c11 {
  strings:
    $key_0c11 = { 5f 7e [2] 7b 70 [2] 50 5c [2] 7e 7e [2] 6a 65 [2] 65 7f [2] 7b 62 [2] 79 63 [2] 62 65 [2] 7e 62 [2] 62 4d }

  condition:
    any of them
}