rule TTP_XOR_QUAD_CurrentVersionRun_dbea {
  strings:
    $key_dbea = { 88 85 [2] ac 8b [2] 87 a7 [2] a9 85 [2] bd 9e [2] b2 84 [2] ac 99 [2] ae 98 [2] b5 9e [2] a9 99 [2] b5 b6 }

  condition:
    any of them
}