rule TTP_XOR_QUAD_CurrentVersionRun_0533 {
  strings:
    $key_0533 = { 56 5c [2] 72 52 [2] 59 7e [2] 77 5c [2] 63 47 [2] 6c 5d [2] 72 40 [2] 70 41 [2] 6b 47 [2] 77 40 [2] 6b 6f }

  condition:
    any of them
}