rule TTP_XOR_QUAD_CurrentVersionRun_db02 {
  strings:
    $key_db02 = { 88 6d [2] ac 63 [2] 87 4f [2] a9 6d [2] bd 76 [2] b2 6c [2] ac 71 [2] ae 70 [2] b5 76 [2] a9 71 [2] b5 5e }

  condition:
    any of them
}