rule TTP_XOR_QUAD_CurrentVersionRun_400f {
  strings:
    $key_400f = { 13 60 [2] 37 6e [2] 1c 42 [2] 32 60 [2] 26 7b [2] 29 61 [2] 37 7c [2] 35 7d [2] 2e 7b [2] 32 7c [2] 2e 53 }

  condition:
    any of them
}