rule TTP_XOR_QUAD_CurrentVersionRun_3e21 {
  strings:
    $key_3e21 = { 6d 4e [2] 49 40 [2] 62 6c [2] 4c 4e [2] 58 55 [2] 57 4f [2] 49 52 [2] 4b 53 [2] 50 55 [2] 4c 52 [2] 50 7d }

  condition:
    any of them
}