rule TTP_XOR_QUAD_CurrentVersionRun_dbf9 {
  strings:
    $key_dbf9 = { 88 96 [2] ac 98 [2] 87 b4 [2] a9 96 [2] bd 8d [2] b2 97 [2] ac 8a [2] ae 8b [2] b5 8d [2] a9 8a [2] b5 a5 }

  condition:
    any of them
}