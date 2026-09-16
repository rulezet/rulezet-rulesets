rule TTP_XOR_QUAD_CurrentVersionRun_fdff {
  strings:
    $key_fdff = { ae 90 [2] 8a 9e [2] a1 b2 [2] 8f 90 [2] 9b 8b [2] 94 91 [2] 8a 8c [2] 88 8d [2] 93 8b [2] 8f 8c [2] 93 a3 }

  condition:
    any of them
}