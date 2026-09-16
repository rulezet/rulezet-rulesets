rule TTP_XOR_QUAD_CurrentVersionRun_2e40 {
  strings:
    $key_2e40 = { 7d 2f [2] 59 21 [2] 72 0d [2] 5c 2f [2] 48 34 [2] 47 2e [2] 59 33 [2] 5b 32 [2] 40 34 [2] 5c 33 [2] 40 1c }

  condition:
    any of them
}