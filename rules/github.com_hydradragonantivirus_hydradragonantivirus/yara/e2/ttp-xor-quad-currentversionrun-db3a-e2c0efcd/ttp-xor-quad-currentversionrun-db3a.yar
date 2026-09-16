rule TTP_XOR_QUAD_CurrentVersionRun_db3a {
  strings:
    $key_db3a = { 88 55 [2] ac 5b [2] 87 77 [2] a9 55 [2] bd 4e [2] b2 54 [2] ac 49 [2] ae 48 [2] b5 4e [2] a9 49 [2] b5 66 }

  condition:
    any of them
}