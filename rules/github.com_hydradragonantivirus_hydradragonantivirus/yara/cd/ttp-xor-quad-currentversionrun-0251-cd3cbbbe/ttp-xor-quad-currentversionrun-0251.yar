rule TTP_XOR_QUAD_CurrentVersionRun_0251 {
  strings:
    $key_0251 = { 51 3e [2] 75 30 [2] 5e 1c [2] 70 3e [2] 64 25 [2] 6b 3f [2] 75 22 [2] 77 23 [2] 6c 25 [2] 70 22 [2] 6c 0d }

  condition:
    any of them
}