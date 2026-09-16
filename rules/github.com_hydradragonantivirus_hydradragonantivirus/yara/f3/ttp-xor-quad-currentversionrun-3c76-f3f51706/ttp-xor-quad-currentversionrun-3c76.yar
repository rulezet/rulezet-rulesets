rule TTP_XOR_QUAD_CurrentVersionRun_3c76 {
  strings:
    $key_3c76 = { 6f 19 [2] 4b 17 [2] 60 3b [2] 4e 19 [2] 5a 02 [2] 55 18 [2] 4b 05 [2] 49 04 [2] 52 02 [2] 4e 05 [2] 52 2a }

  condition:
    any of them
}