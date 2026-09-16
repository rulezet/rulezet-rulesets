rule TTP_XOR_QUAD_CurrentVersionRun_6621 {
  strings:
    $key_6621 = { 35 4e [2] 11 40 [2] 3a 6c [2] 14 4e [2] 00 55 [2] 0f 4f [2] 11 52 [2] 13 53 [2] 08 55 [2] 14 52 [2] 08 7d }

  condition:
    any of them
}