rule TTP_XOR_QUAD_CurrentVersionRun_0b21 {
  strings:
    $key_0b21 = { 58 4e [2] 7c 40 [2] 57 6c [2] 79 4e [2] 6d 55 [2] 62 4f [2] 7c 52 [2] 7e 53 [2] 65 55 [2] 79 52 [2] 65 7d }

  condition:
    any of them
}