rule TTP_XOR_QUAD_CurrentVersionRun_220f {
  strings:
    $key_220f = { 71 60 [2] 55 6e [2] 7e 42 [2] 50 60 [2] 44 7b [2] 4b 61 [2] 55 7c [2] 57 7d [2] 4c 7b [2] 50 7c [2] 4c 53 }

  condition:
    any of them
}