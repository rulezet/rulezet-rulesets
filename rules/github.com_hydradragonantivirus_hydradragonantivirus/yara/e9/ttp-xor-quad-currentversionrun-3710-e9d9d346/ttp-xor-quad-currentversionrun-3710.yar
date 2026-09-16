rule TTP_XOR_QUAD_CurrentVersionRun_3710 {
  strings:
    $key_3710 = { 64 7f [2] 40 71 [2] 6b 5d [2] 45 7f [2] 51 64 [2] 5e 7e [2] 40 63 [2] 42 62 [2] 59 64 [2] 45 63 [2] 59 4c }

  condition:
    any of them
}