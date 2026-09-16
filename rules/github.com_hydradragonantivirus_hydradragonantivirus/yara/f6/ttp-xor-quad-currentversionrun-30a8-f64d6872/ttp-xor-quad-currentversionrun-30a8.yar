rule TTP_XOR_QUAD_CurrentVersionRun_30a8 {
  strings:
    $key_30a8 = { 63 c7 [2] 47 c9 [2] 6c e5 [2] 42 c7 [2] 56 dc [2] 59 c6 [2] 47 db [2] 45 da [2] 5e dc [2] 42 db [2] 5e f4 }

  condition:
    any of them
}