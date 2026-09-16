rule TTP_XOR_QUAD_CurrentVersionRun_f20c {
  strings:
    $key_f20c = { a1 63 [2] 85 6d [2] ae 41 [2] 80 63 [2] 94 78 [2] 9b 62 [2] 85 7f [2] 87 7e [2] 9c 78 [2] 80 7f [2] 9c 50 }

  condition:
    any of them
}