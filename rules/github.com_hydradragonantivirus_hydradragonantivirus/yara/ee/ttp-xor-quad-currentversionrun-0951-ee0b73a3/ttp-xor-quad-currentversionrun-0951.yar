rule TTP_XOR_QUAD_CurrentVersionRun_0951 {
  strings:
    $key_0951 = { 5a 3e [2] 7e 30 [2] 55 1c [2] 7b 3e [2] 6f 25 [2] 60 3f [2] 7e 22 [2] 7c 23 [2] 67 25 [2] 7b 22 [2] 67 0d }

  condition:
    any of them
}