rule TTP_XOR_QUAD_CurrentVersionRun_3b51 {
  strings:
    $key_3b51 = { 68 3e [2] 4c 30 [2] 67 1c [2] 49 3e [2] 5d 25 [2] 52 3f [2] 4c 22 [2] 4e 23 [2] 55 25 [2] 49 22 [2] 55 0d }

  condition:
    any of them
}