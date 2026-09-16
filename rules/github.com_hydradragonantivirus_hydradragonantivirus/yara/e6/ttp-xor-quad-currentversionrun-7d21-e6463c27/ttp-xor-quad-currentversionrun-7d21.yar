rule TTP_XOR_QUAD_CurrentVersionRun_7d21 {
  strings:
    $key_7d21 = { 2e 4e [2] 0a 40 [2] 21 6c [2] 0f 4e [2] 1b 55 [2] 14 4f [2] 0a 52 [2] 08 53 [2] 13 55 [2] 0f 52 [2] 13 7d }

  condition:
    any of them
}