rule TTP_XOR_QUAD_CurrentVersionRun_2696 {
  strings:
    $key_2696 = { 75 f9 [2] 51 f7 [2] 7a db [2] 54 f9 [2] 40 e2 [2] 4f f8 [2] 51 e5 [2] 53 e4 [2] 48 e2 [2] 54 e5 [2] 48 ca }

  condition:
    any of them
}