rule TTP_XOR_QUAD_CurrentVersionRun_4821 {
  strings:
    $key_4821 = { 1b 4e [2] 3f 40 [2] 14 6c [2] 3a 4e [2] 2e 55 [2] 21 4f [2] 3f 52 [2] 3d 53 [2] 26 55 [2] 3a 52 [2] 26 7d }

  condition:
    any of them
}