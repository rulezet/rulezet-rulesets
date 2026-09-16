rule TTP_XOR_QUAD_CurrentVersionRun_024a {
  strings:
    $key_024a = { 51 25 [2] 75 2b [2] 5e 07 [2] 70 25 [2] 64 3e [2] 6b 24 [2] 75 39 [2] 77 38 [2] 6c 3e [2] 70 39 [2] 6c 16 }

  condition:
    any of them
}