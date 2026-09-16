rule TTP_XOR_QUAD_CurrentVersionRun_2113 {
  strings:
    $key_2113 = { 72 7c [2] 56 72 [2] 7d 5e [2] 53 7c [2] 47 67 [2] 48 7d [2] 56 60 [2] 54 61 [2] 4f 67 [2] 53 60 [2] 4f 4f }

  condition:
    any of them
}