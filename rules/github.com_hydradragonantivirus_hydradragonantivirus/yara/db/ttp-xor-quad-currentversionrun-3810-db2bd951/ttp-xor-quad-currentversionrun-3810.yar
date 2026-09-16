rule TTP_XOR_QUAD_CurrentVersionRun_3810 {
  strings:
    $key_3810 = { 6b 7f [2] 4f 71 [2] 64 5d [2] 4a 7f [2] 5e 64 [2] 51 7e [2] 4f 63 [2] 4d 62 [2] 56 64 [2] 4a 63 [2] 56 4c }

  condition:
    any of them
}