rule TTP_XOR_QUAD_CurrentVersionRun_0011 {
  strings:
    $key_0011 = { 53 7e [2] 77 70 [2] 5c 5c [2] 72 7e [2] 66 65 [2] 69 7f [2] 77 62 [2] 75 63 [2] 6e 65 [2] 72 62 [2] 6e 4d }

  condition:
    any of them
}