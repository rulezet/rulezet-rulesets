rule TTP_XOR_QUAD_CurrentVersionRun_db2e {
  strings:
    $key_db2e = { 88 41 [2] ac 4f [2] 87 63 [2] a9 41 [2] bd 5a [2] b2 40 [2] ac 5d [2] ae 5c [2] b5 5a [2] a9 5d [2] b5 72 }

  condition:
    any of them
}