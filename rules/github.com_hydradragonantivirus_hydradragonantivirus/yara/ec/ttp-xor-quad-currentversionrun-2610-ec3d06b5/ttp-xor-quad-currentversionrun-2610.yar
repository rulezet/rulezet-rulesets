rule TTP_XOR_QUAD_CurrentVersionRun_2610 {
  strings:
    $key_2610 = { 75 7f [2] 51 71 [2] 7a 5d [2] 54 7f [2] 40 64 [2] 4f 7e [2] 51 63 [2] 53 62 [2] 48 64 [2] 54 63 [2] 48 4c }

  condition:
    any of them
}