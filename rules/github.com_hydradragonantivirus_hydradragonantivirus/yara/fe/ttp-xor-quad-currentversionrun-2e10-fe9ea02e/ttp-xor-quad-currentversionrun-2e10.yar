rule TTP_XOR_QUAD_CurrentVersionRun_2e10 {
  strings:
    $key_2e10 = { 7d 7f [2] 59 71 [2] 72 5d [2] 5c 7f [2] 48 64 [2] 47 7e [2] 59 63 [2] 5b 62 [2] 40 64 [2] 5c 63 [2] 40 4c }

  condition:
    any of them
}