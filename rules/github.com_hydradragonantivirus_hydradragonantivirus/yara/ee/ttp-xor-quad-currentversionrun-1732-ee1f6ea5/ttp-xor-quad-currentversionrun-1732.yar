rule TTP_XOR_QUAD_CurrentVersionRun_1732 {
  strings:
    $key_1732 = { 44 5d [2] 60 53 [2] 4b 7f [2] 65 5d [2] 71 46 [2] 7e 5c [2] 60 41 [2] 62 40 [2] 79 46 [2] 65 41 [2] 79 6e }

  condition:
    any of them
}