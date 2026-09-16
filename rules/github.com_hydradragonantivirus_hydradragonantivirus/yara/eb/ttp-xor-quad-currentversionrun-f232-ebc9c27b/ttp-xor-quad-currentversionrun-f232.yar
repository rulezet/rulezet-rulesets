rule TTP_XOR_QUAD_CurrentVersionRun_f232 {
  strings:
    $key_f232 = { a1 5d [2] 85 53 [2] ae 7f [2] 80 5d [2] 94 46 [2] 9b 5c [2] 85 41 [2] 87 40 [2] 9c 46 [2] 80 41 [2] 9c 6e }

  condition:
    any of them
}