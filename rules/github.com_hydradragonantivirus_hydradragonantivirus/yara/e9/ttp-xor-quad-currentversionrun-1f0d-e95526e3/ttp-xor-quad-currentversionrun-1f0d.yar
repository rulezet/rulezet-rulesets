rule TTP_XOR_QUAD_CurrentVersionRun_1f0d {
  strings:
    $key_1f0d = { 4c 62 [2] 68 6c [2] 43 40 [2] 6d 62 [2] 79 79 [2] 76 63 [2] 68 7e [2] 6a 7f [2] 71 79 [2] 6d 7e [2] 71 51 }

  condition:
    any of them
}