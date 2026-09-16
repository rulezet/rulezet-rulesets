rule TTP_XOR_QUAD_CurrentVersionRun_62a8 {
  strings:
    $key_62a8 = { 31 c7 [2] 15 c9 [2] 3e e5 [2] 10 c7 [2] 04 dc [2] 0b c6 [2] 15 db [2] 17 da [2] 0c dc [2] 10 db [2] 0c f4 }

  condition:
    any of them
}