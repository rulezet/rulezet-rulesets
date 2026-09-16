rule TTP_XOR_QUAD_CurrentVersionRun_2613 {
  strings:
    $key_2613 = { 75 7c [2] 51 72 [2] 7a 5e [2] 54 7c [2] 40 67 [2] 4f 7d [2] 51 60 [2] 53 61 [2] 48 67 [2] 54 60 [2] 48 4f }

  condition:
    any of them
}