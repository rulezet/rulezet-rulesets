rule TTP_XOR_QUAD_CurrentVersionRun_0f51 {
  strings:
    $key_0f51 = { 5c 3e [2] 78 30 [2] 53 1c [2] 7d 3e [2] 69 25 [2] 66 3f [2] 78 22 [2] 7a 23 [2] 61 25 [2] 7d 22 [2] 61 0d }

  condition:
    any of them
}