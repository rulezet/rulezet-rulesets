rule TTP_XOR_QUAD_CurrentVersionRun_21fa {
  strings:
    $key_21fa = { 72 95 [2] 56 9b [2] 7d b7 [2] 53 95 [2] 47 8e [2] 48 94 [2] 56 89 [2] 54 88 [2] 4f 8e [2] 53 89 [2] 4f a6 }

  condition:
    any of them
}