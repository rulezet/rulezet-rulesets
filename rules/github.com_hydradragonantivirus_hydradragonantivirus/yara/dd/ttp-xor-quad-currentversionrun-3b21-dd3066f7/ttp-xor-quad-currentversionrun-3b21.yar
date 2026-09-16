rule TTP_XOR_QUAD_CurrentVersionRun_3b21 {
  strings:
    $key_3b21 = { 68 4e [2] 4c 40 [2] 67 6c [2] 49 4e [2] 5d 55 [2] 52 4f [2] 4c 52 [2] 4e 53 [2] 55 55 [2] 49 52 [2] 55 7d }

  condition:
    any of them
}