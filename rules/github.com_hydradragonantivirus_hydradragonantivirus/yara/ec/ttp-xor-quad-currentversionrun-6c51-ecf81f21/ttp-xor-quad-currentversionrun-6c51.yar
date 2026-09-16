rule TTP_XOR_QUAD_CurrentVersionRun_6c51 {
  strings:
    $key_6c51 = { 3f 3e [2] 1b 30 [2] 30 1c [2] 1e 3e [2] 0a 25 [2] 05 3f [2] 1b 22 [2] 19 23 [2] 02 25 [2] 1e 22 [2] 02 0d }

  condition:
    any of them
}