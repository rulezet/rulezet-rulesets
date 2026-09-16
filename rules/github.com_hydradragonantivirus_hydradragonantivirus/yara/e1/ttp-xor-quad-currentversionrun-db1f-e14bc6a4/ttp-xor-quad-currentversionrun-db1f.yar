rule TTP_XOR_QUAD_CurrentVersionRun_db1f {
  strings:
    $key_db1f = { 88 70 [2] ac 7e [2] 87 52 [2] a9 70 [2] bd 6b [2] b2 71 [2] ac 6c [2] ae 6d [2] b5 6b [2] a9 6c [2] b5 43 }

  condition:
    any of them
}