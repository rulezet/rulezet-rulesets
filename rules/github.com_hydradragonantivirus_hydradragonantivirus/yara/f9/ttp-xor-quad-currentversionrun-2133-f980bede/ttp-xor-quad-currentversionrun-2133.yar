rule TTP_XOR_QUAD_CurrentVersionRun_2133 {
  strings:
    $key_2133 = { 72 5c [2] 56 52 [2] 7d 7e [2] 53 5c [2] 47 47 [2] 48 5d [2] 56 40 [2] 54 41 [2] 4f 47 [2] 53 40 [2] 4f 6f }

  condition:
    any of them
}