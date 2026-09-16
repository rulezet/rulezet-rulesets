rule TTP_XOR_QUAD_CurrentVersionRun_2633 {
  strings:
    $key_2633 = { 75 5c [2] 51 52 [2] 7a 7e [2] 54 5c [2] 40 47 [2] 4f 5d [2] 51 40 [2] 53 41 [2] 48 47 [2] 54 40 [2] 48 6f }

  condition:
    any of them
}