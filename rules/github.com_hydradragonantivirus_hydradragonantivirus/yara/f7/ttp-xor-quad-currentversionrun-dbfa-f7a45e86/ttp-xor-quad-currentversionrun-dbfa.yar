rule TTP_XOR_QUAD_CurrentVersionRun_dbfa {
  strings:
    $key_dbfa = { 88 95 [2] ac 9b [2] 87 b7 [2] a9 95 [2] bd 8e [2] b2 94 [2] ac 89 [2] ae 88 [2] b5 8e [2] a9 89 [2] b5 a6 }

  condition:
    any of them
}