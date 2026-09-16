rule TTP_XOR_QUAD_CurrentVersionRun_0876 {
  strings:
    $key_0876 = { 5b 19 [2] 7f 17 [2] 54 3b [2] 7a 19 [2] 6e 02 [2] 61 18 [2] 7f 05 [2] 7d 04 [2] 66 02 [2] 7a 05 [2] 66 2a }

  condition:
    any of them
}