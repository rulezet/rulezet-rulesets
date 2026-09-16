rule TTP_XOR_QUAD_CurrentVersionRun_ef76 {
  strings:
    $key_ef76 = { bc 19 [2] 98 17 [2] b3 3b [2] 9d 19 [2] 89 02 [2] 86 18 [2] 98 05 [2] 9a 04 [2] 81 02 [2] 9d 05 [2] 81 2a }

  condition:
    any of them
}