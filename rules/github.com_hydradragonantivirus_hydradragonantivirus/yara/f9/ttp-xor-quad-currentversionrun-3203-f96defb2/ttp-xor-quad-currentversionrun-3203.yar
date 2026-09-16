rule TTP_XOR_QUAD_CurrentVersionRun_3203 {
  strings:
    $key_3203 = { 61 6c [2] 45 62 [2] 6e 4e [2] 40 6c [2] 54 77 [2] 5b 6d [2] 45 70 [2] 47 71 [2] 5c 77 [2] 40 70 [2] 5c 5f }

  condition:
    any of them
}