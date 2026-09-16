rule TTP_XOR_QUAD_CurrentVersionRun_db06 {
  strings:
    $key_db06 = { 88 69 [2] ac 67 [2] 87 4b [2] a9 69 [2] bd 72 [2] b2 68 [2] ac 75 [2] ae 74 [2] b5 72 [2] a9 75 [2] b5 5a }

  condition:
    any of them
}