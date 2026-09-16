rule TTP_XOR_QUAD_CurrentVersionRun_2331 {
  strings:
    $key_2331 = { 70 5e [2] 54 50 [2] 7f 7c [2] 51 5e [2] 45 45 [2] 4a 5f [2] 54 42 [2] 56 43 [2] 4d 45 [2] 51 42 [2] 4d 6d }

  condition:
    any of them
}