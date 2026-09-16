rule TTP_XOR_QUAD_CurrentVersionRun_1921 {
  strings:
    $key_1921 = { 4a 4e [2] 6e 40 [2] 45 6c [2] 6b 4e [2] 7f 55 [2] 70 4f [2] 6e 52 [2] 6c 53 [2] 77 55 [2] 6b 52 [2] 77 7d }

  condition:
    any of them
}