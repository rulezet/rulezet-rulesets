rule TTP_XOR_QUAD_CurrentVersionRun_3010 {
  strings:
    $key_3010 = { 63 7f [2] 47 71 [2] 6c 5d [2] 42 7f [2] 56 64 [2] 59 7e [2] 47 63 [2] 45 62 [2] 5e 64 [2] 42 63 [2] 5e 4c }

  condition:
    any of them
}