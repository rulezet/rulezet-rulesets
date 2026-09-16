rule TTP_XOR_QUAD_CurrentVersionRun_5202 {
  strings:
    $key_5202 = { 01 6d [2] 25 63 [2] 0e 4f [2] 20 6d [2] 34 76 [2] 3b 6c [2] 25 71 [2] 27 70 [2] 3c 76 [2] 20 71 [2] 3c 5e }

  condition:
    any of them
}