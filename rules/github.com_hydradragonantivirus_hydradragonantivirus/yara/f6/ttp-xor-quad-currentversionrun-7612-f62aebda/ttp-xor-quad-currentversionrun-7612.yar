rule TTP_XOR_QUAD_CurrentVersionRun_7612 {
  strings:
    $key_7612 = { 25 7d [2] 01 73 [2] 2a 5f [2] 04 7d [2] 10 66 [2] 1f 7c [2] 01 61 [2] 03 60 [2] 18 66 [2] 04 61 [2] 18 4e }

  condition:
    any of them
}