rule TTP_XOR_QUAD_CurrentVersionRun_dbfd {
  strings:
    $key_dbfd = { 88 92 [2] ac 9c [2] 87 b0 [2] a9 92 [2] bd 89 [2] b2 93 [2] ac 8e [2] ae 8f [2] b5 89 [2] a9 8e [2] b5 a1 }

  condition:
    any of them
}