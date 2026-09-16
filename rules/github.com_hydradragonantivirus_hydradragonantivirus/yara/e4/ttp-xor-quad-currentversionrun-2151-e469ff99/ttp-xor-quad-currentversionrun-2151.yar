rule TTP_XOR_QUAD_CurrentVersionRun_2151 {
  strings:
    $key_2151 = { 72 3e [2] 56 30 [2] 7d 1c [2] 53 3e [2] 47 25 [2] 48 3f [2] 56 22 [2] 54 23 [2] 4f 25 [2] 53 22 [2] 4f 0d }

  condition:
    any of them
}