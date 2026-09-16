rule TTP_XOR_QUAD_CurrentVersionRun_3310 {
  strings:
    $key_3310 = { 60 7f [2] 44 71 [2] 6f 5d [2] 41 7f [2] 55 64 [2] 5a 7e [2] 44 63 [2] 46 62 [2] 5d 64 [2] 41 63 [2] 5d 4c }

  condition:
    any of them
}