rule TTP_XOR_QUAD_CurrentVersionRun_5622 {
  strings:
    $key_5622 = { 05 4d [2] 21 43 [2] 0a 6f [2] 24 4d [2] 30 56 [2] 3f 4c [2] 21 51 [2] 23 50 [2] 38 56 [2] 24 51 [2] 38 7e }

  condition:
    any of them
}