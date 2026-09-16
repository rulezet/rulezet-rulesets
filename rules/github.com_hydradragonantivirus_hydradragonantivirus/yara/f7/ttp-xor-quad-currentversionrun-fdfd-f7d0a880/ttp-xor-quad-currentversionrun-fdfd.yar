rule TTP_XOR_QUAD_CurrentVersionRun_fdfd {
  strings:
    $key_fdfd = { ae 92 [2] 8a 9c [2] a1 b0 [2] 8f 92 [2] 9b 89 [2] 94 93 [2] 8a 8e [2] 88 8f [2] 93 89 [2] 8f 8e [2] 93 a1 }

  condition:
    any of them
}