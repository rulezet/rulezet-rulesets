rule TTP_XOR_QUAD_CurrentVersionRun_1440 {
  strings:
    $key_1440 = { 47 2f [2] 63 21 [2] 48 0d [2] 66 2f [2] 72 34 [2] 7d 2e [2] 63 33 [2] 61 32 [2] 7a 34 [2] 66 33 [2] 7a 1c }

  condition:
    any of them
}