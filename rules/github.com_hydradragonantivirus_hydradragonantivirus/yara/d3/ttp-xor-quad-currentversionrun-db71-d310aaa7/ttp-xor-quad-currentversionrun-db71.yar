rule TTP_XOR_QUAD_CurrentVersionRun_db71 {
  strings:
    $key_db71 = { 88 1e [2] ac 10 [2] 87 3c [2] a9 1e [2] bd 05 [2] b2 1f [2] ac 02 [2] ae 03 [2] b5 05 [2] a9 02 [2] b5 2d }

  condition:
    any of them
}