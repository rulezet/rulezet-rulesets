rule TTP_XOR_QUAD_CurrentVersionRun_f432 {
  strings:
    $key_f432 = { a7 5d [2] 83 53 [2] a8 7f [2] 86 5d [2] 92 46 [2] 9d 5c [2] 83 41 [2] 81 40 [2] 9a 46 [2] 86 41 [2] 9a 6e }

  condition:
    any of them
}