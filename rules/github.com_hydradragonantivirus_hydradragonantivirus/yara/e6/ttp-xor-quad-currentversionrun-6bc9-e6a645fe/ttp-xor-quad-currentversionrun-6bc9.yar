rule TTP_XOR_QUAD_CurrentVersionRun_6bc9 {
  strings:
    $key_6bc9 = { 38 a6 [2] 1c a8 [2] 37 84 [2] 19 a6 [2] 0d bd [2] 02 a7 [2] 1c ba [2] 1e bb [2] 05 bd [2] 19 ba [2] 05 95 }

  condition:
    any of them
}