rule TTP_XOR_QUAD_CurrentVersionRun_504a {
  strings:
    $key_504a = { 03 25 [2] 27 2b [2] 0c 07 [2] 22 25 [2] 36 3e [2] 39 24 [2] 27 39 [2] 25 38 [2] 3e 3e [2] 22 39 [2] 3e 16 }

  condition:
    any of them
}