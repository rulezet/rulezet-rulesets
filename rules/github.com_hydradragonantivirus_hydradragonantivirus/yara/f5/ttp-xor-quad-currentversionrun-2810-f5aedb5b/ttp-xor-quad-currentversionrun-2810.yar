rule TTP_XOR_QUAD_CurrentVersionRun_2810 {
  strings:
    $key_2810 = { 7b 7f [2] 5f 71 [2] 74 5d [2] 5a 7f [2] 4e 64 [2] 41 7e [2] 5f 63 [2] 5d 62 [2] 46 64 [2] 5a 63 [2] 46 4c }

  condition:
    any of them
}