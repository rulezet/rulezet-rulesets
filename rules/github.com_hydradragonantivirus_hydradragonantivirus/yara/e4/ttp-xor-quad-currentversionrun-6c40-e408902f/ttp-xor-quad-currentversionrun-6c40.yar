rule TTP_XOR_QUAD_CurrentVersionRun_6c40 {
  strings:
    $key_6c40 = { 3f 2f [2] 1b 21 [2] 30 0d [2] 1e 2f [2] 0a 34 [2] 05 2e [2] 1b 33 [2] 19 32 [2] 02 34 [2] 1e 33 [2] 02 1c }

  condition:
    any of them
}