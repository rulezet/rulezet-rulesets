rule TTP_XOR_QUAD_CurrentVersionRun_1971 {
  strings:
    $key_1971 = { 4a 1e [2] 6e 10 [2] 45 3c [2] 6b 1e [2] 7f 05 [2] 70 1f [2] 6e 02 [2] 6c 03 [2] 77 05 [2] 6b 02 [2] 77 2d }

  condition:
    any of them
}