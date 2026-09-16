rule TTP_XOR_QUAD_CurrentVersionRun_450f {
  strings:
    $key_450f = { 16 60 [2] 32 6e [2] 19 42 [2] 37 60 [2] 23 7b [2] 2c 61 [2] 32 7c [2] 30 7d [2] 2b 7b [2] 37 7c [2] 2b 53 }

  condition:
    any of them
}