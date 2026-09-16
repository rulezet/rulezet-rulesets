rule TTP_XOR_QUAD_CurrentVersionRun_2832 {
  strings:
    $key_2832 = { 7b 5d [2] 5f 53 [2] 74 7f [2] 5a 5d [2] 4e 46 [2] 41 5c [2] 5f 41 [2] 5d 40 [2] 46 46 [2] 5a 41 [2] 46 6e }

  condition:
    any of them
}