rule TTP_XOR_QUAD_CurrentVersionRun_1422 {
  strings:
    $key_1422 = { 47 4d [2] 63 43 [2] 48 6f [2] 66 4d [2] 72 56 [2] 7d 4c [2] 63 51 [2] 61 50 [2] 7a 56 [2] 66 51 [2] 7a 7e }

  condition:
    any of them
}