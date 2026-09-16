rule TTP_XOR_QUAD_CurrentVersionRun_4321 {
  strings:
    $key_4321 = { 10 4e [2] 34 40 [2] 1f 6c [2] 31 4e [2] 25 55 [2] 2a 4f [2] 34 52 [2] 36 53 [2] 2d 55 [2] 31 52 [2] 2d 7d }

  condition:
    any of them
}