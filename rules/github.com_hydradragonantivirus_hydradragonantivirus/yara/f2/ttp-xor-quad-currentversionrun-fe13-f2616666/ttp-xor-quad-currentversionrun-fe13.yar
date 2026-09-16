rule TTP_XOR_QUAD_CurrentVersionRun_fe13 {
  strings:
    $key_fe13 = { ad 7c [2] 89 72 [2] a2 5e [2] 8c 7c [2] 98 67 [2] 97 7d [2] 89 60 [2] 8b 61 [2] 90 67 [2] 8c 60 [2] 90 4f }

  condition:
    any of them
}