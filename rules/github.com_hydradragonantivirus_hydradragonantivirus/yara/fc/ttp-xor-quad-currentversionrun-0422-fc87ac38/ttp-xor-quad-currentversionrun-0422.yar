rule TTP_XOR_QUAD_CurrentVersionRun_0422 {
  strings:
    $key_0422 = { 57 4d [2] 73 43 [2] 58 6f [2] 76 4d [2] 62 56 [2] 6d 4c [2] 73 51 [2] 71 50 [2] 6a 56 [2] 76 51 [2] 6a 7e }

  condition:
    any of them
}