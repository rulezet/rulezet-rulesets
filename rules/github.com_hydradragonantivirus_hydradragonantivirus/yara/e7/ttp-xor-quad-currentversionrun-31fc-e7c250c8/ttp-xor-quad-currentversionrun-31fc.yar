rule TTP_XOR_QUAD_CurrentVersionRun_31fc {
  strings:
    $key_31fc = { 62 93 [2] 46 9d [2] 6d b1 [2] 43 93 [2] 57 88 [2] 58 92 [2] 46 8f [2] 44 8e [2] 5f 88 [2] 43 8f [2] 5f a0 }

  condition:
    any of them
}