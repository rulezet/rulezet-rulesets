rule TTP_XOR_QUAD_CurrentVersionRun_4b31 {
  strings:
    $key_4b31 = { 18 5e [2] 3c 50 [2] 17 7c [2] 39 5e [2] 2d 45 [2] 22 5f [2] 3c 42 [2] 3e 43 [2] 25 45 [2] 39 42 [2] 25 6d }

  condition:
    any of them
}