rule TTP_XOR_QUAD_CurrentVersionRun_2702 {
  strings:
    $key_2702 = { 74 6d [2] 50 63 [2] 7b 4f [2] 55 6d [2] 41 76 [2] 4e 6c [2] 50 71 [2] 52 70 [2] 49 76 [2] 55 71 [2] 49 5e }

  condition:
    any of them
}