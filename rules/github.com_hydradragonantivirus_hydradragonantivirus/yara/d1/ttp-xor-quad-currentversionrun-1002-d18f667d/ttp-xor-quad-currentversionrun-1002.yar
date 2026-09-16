rule TTP_XOR_QUAD_CurrentVersionRun_1002 {
  strings:
    $key_1002 = { 43 6d [2] 67 63 [2] 4c 4f [2] 62 6d [2] 76 76 [2] 79 6c [2] 67 71 [2] 65 70 [2] 7e 76 [2] 62 71 [2] 7e 5e }

  condition:
    any of them
}