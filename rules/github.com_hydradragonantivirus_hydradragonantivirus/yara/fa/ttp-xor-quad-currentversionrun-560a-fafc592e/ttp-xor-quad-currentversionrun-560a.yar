rule TTP_XOR_QUAD_CurrentVersionRun_560a {
  strings:
    $key_560a = { 05 65 [2] 21 6b [2] 0a 47 [2] 24 65 [2] 30 7e [2] 3f 64 [2] 21 79 [2] 23 78 [2] 38 7e [2] 24 79 [2] 38 56 }

  condition:
    any of them
}