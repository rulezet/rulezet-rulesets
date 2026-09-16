rule TTP_XOR_QUAD_CurrentVersionRun_0851 {
  strings:
    $key_0851 = { 5b 3e [2] 7f 30 [2] 54 1c [2] 7a 3e [2] 6e 25 [2] 61 3f [2] 7f 22 [2] 7d 23 [2] 66 25 [2] 7a 22 [2] 66 0d }

  condition:
    any of them
}