rule TTP_XOR_QUAD_CurrentVersionRun_3c51 {
  strings:
    $key_3c51 = { 6f 3e [2] 4b 30 [2] 60 1c [2] 4e 3e [2] 5a 25 [2] 55 3f [2] 4b 22 [2] 49 23 [2] 52 25 [2] 4e 22 [2] 52 0d }

  condition:
    any of them
}