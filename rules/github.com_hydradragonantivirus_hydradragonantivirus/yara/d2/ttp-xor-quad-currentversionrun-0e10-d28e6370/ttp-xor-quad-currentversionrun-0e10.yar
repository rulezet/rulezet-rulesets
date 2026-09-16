rule TTP_XOR_QUAD_CurrentVersionRun_0e10 {
  strings:
    $key_0e10 = { 5d 7f [2] 79 71 [2] 52 5d [2] 7c 7f [2] 68 64 [2] 67 7e [2] 79 63 [2] 7b 62 [2] 60 64 [2] 7c 63 [2] 60 4c }

  condition:
    any of them
}