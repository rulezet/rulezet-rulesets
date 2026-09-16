rule TTP_XOR_QUAD_CurrentVersionRun_2362 {
  strings:
    $key_2362 = { 70 0d [2] 54 03 [2] 7f 2f [2] 51 0d [2] 45 16 [2] 4a 0c [2] 54 11 [2] 56 10 [2] 4d 16 [2] 51 11 [2] 4d 3e }

  condition:
    any of them
}