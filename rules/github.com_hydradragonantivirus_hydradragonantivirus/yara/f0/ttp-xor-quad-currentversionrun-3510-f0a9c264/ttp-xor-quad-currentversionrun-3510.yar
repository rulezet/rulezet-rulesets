rule TTP_XOR_QUAD_CurrentVersionRun_3510 {
  strings:
    $key_3510 = { 66 7f [2] 42 71 [2] 69 5d [2] 47 7f [2] 53 64 [2] 5c 7e [2] 42 63 [2] 40 62 [2] 5b 64 [2] 47 63 [2] 5b 4c }

  condition:
    any of them
}