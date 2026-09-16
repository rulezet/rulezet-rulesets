rule TTP_XOR_QUAD_CurrentVersionRun_1b21 {
  strings:
    $key_1b21 = { 48 4e [2] 6c 40 [2] 47 6c [2] 69 4e [2] 7d 55 [2] 72 4f [2] 6c 52 [2] 6e 53 [2] 75 55 [2] 69 52 [2] 75 7d }

  condition:
    any of them
}