rule TTP_XOR_QUAD_CurrentVersionRun_defa {
  strings:
    $key_defa = { 8d 95 [2] a9 9b [2] 82 b7 [2] ac 95 [2] b8 8e [2] b7 94 [2] a9 89 [2] ab 88 [2] b0 8e [2] ac 89 [2] b0 a6 }

  condition:
    any of them
}