rule TTP_XOR_QUAD_CurrentVersionRun_f876 {
  strings:
    $key_f876 = { ab 19 [2] 8f 17 [2] a4 3b [2] 8a 19 [2] 9e 02 [2] 91 18 [2] 8f 05 [2] 8d 04 [2] 96 02 [2] 8a 05 [2] 96 2a }

  condition:
    any of them
}