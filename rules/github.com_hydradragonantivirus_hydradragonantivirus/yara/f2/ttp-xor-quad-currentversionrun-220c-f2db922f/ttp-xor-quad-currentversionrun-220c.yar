rule TTP_XOR_QUAD_CurrentVersionRun_220c {
  strings:
    $key_220c = { 71 63 [2] 55 6d [2] 7e 41 [2] 50 63 [2] 44 78 [2] 4b 62 [2] 55 7f [2] 57 7e [2] 4c 78 [2] 50 7f [2] 4c 50 }

  condition:
    any of them
}