rule TTP_XOR_QUAD_CurrentVersionRun_6632 {
  strings:
    $key_6632 = { 35 5d [2] 11 53 [2] 3a 7f [2] 14 5d [2] 00 46 [2] 0f 5c [2] 11 41 [2] 13 40 [2] 08 46 [2] 14 41 [2] 08 6e }

  condition:
    any of them
}