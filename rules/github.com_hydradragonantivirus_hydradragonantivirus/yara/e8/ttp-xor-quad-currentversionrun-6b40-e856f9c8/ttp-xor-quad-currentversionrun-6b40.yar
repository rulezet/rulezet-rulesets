rule TTP_XOR_QUAD_CurrentVersionRun_6b40 {
  strings:
    $key_6b40 = { 38 2f [2] 1c 21 [2] 37 0d [2] 19 2f [2] 0d 34 [2] 02 2e [2] 1c 33 [2] 1e 32 [2] 05 34 [2] 19 33 [2] 05 1c }

  condition:
    any of them
}