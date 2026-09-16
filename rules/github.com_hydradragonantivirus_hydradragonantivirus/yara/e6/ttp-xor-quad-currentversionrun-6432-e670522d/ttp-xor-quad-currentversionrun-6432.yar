rule TTP_XOR_QUAD_CurrentVersionRun_6432 {
  strings:
    $key_6432 = { 37 5d [2] 13 53 [2] 38 7f [2] 16 5d [2] 02 46 [2] 0d 5c [2] 13 41 [2] 11 40 [2] 0a 46 [2] 16 41 [2] 0a 6e }

  condition:
    any of them
}