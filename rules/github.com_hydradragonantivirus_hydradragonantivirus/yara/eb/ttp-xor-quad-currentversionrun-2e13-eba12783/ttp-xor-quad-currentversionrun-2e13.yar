rule TTP_XOR_QUAD_CurrentVersionRun_2e13 {
  strings:
    $key_2e13 = { 7d 7c [2] 59 72 [2] 72 5e [2] 5c 7c [2] 48 67 [2] 47 7d [2] 59 60 [2] 5b 61 [2] 40 67 [2] 5c 60 [2] 40 4f }

  condition:
    any of them
}