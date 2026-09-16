rule TTP_XOR_QUAD_CurrentVersionRun_6b22 {
  strings:
    $key_6b22 = { 38 4d [2] 1c 43 [2] 37 6f [2] 19 4d [2] 0d 56 [2] 02 4c [2] 1c 51 [2] 1e 50 [2] 05 56 [2] 19 51 [2] 05 7e }

  condition:
    any of them
}