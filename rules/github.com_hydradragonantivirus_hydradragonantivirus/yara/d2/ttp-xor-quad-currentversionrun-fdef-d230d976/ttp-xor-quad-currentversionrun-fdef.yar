rule TTP_XOR_QUAD_CurrentVersionRun_fdef {
  strings:
    $key_fdef = { ae 80 [2] 8a 8e [2] a1 a2 [2] 8f 80 [2] 9b 9b [2] 94 81 [2] 8a 9c [2] 88 9d [2] 93 9b [2] 8f 9c [2] 93 b3 }

  condition:
    any of them
}