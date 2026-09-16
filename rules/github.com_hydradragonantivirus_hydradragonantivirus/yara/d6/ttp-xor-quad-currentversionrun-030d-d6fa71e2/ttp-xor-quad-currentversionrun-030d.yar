rule TTP_XOR_QUAD_CurrentVersionRun_030d {
  strings:
    $key_030d = { 50 62 [2] 74 6c [2] 5f 40 [2] 71 62 [2] 65 79 [2] 6a 63 [2] 74 7e [2] 76 7f [2] 6d 79 [2] 71 7e [2] 6d 51 }

  condition:
    any of them
}