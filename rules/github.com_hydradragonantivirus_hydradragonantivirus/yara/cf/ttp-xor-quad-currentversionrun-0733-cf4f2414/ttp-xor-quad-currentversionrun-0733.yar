rule TTP_XOR_QUAD_CurrentVersionRun_0733 {
  strings:
    $key_0733 = { 54 5c [2] 70 52 [2] 5b 7e [2] 75 5c [2] 61 47 [2] 6e 5d [2] 70 40 [2] 72 41 [2] 69 47 [2] 75 40 [2] 69 6f }

  condition:
    any of them
}