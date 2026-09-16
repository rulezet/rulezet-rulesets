rule TTP_XOR_QUAD_CurrentVersionRun_7d51 {
  strings:
    $key_7d51 = { 2e 3e [2] 0a 30 [2] 21 1c [2] 0f 3e [2] 1b 25 [2] 14 3f [2] 0a 22 [2] 08 23 [2] 13 25 [2] 0f 22 [2] 13 0d }

  condition:
    any of them
}