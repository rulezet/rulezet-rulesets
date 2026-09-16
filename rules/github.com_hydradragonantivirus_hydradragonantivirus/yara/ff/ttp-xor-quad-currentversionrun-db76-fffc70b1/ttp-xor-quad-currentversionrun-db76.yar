rule TTP_XOR_QUAD_CurrentVersionRun_db76 {
  strings:
    $key_db76 = { 88 19 [2] ac 17 [2] 87 3b [2] a9 19 [2] bd 02 [2] b2 18 [2] ac 05 [2] ae 04 [2] b5 02 [2] a9 05 [2] b5 2a }

  condition:
    any of them
}