rule TTP_XOR_QUAD_CurrentVersionRun_3110 {
  strings:
    $key_3110 = { 62 7f [2] 46 71 [2] 6d 5d [2] 43 7f [2] 57 64 [2] 58 7e [2] 46 63 [2] 44 62 [2] 5f 64 [2] 43 63 [2] 5f 4c }

  condition:
    any of them
}