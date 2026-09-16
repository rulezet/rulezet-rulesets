rule TTP_XOR_QUAD_CurrentVersionRun_db10 {
  strings:
    $key_db10 = { 88 7f [2] ac 71 [2] 87 5d [2] a9 7f [2] bd 64 [2] b2 7e [2] ac 63 [2] ae 62 [2] b5 64 [2] a9 63 [2] b5 4c }

  condition:
    any of them
}