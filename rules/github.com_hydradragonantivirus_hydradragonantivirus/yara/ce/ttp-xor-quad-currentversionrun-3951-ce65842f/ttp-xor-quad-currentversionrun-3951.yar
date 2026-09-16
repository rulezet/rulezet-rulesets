rule TTP_XOR_QUAD_CurrentVersionRun_3951 {
  strings:
    $key_3951 = { 6a 3e [2] 4e 30 [2] 65 1c [2] 4b 3e [2] 5f 25 [2] 50 3f [2] 4e 22 [2] 4c 23 [2] 57 25 [2] 4b 22 [2] 57 0d }

  condition:
    any of them
}