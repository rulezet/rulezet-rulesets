rule TTP_XOR_QUAD_CurrentVersionRun_6950 {
  strings:
    $key_6950 = { 3a 3f [2] 1e 31 [2] 35 1d [2] 1b 3f [2] 0f 24 [2] 00 3e [2] 1e 23 [2] 1c 22 [2] 07 24 [2] 1b 23 [2] 07 0c }

  condition:
    any of them
}