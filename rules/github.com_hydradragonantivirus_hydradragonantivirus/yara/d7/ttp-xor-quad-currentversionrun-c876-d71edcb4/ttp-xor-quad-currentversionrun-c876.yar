rule TTP_XOR_QUAD_CurrentVersionRun_c876 {
  strings:
    $key_c876 = { 9b 19 [2] bf 17 [2] 94 3b [2] ba 19 [2] ae 02 [2] a1 18 [2] bf 05 [2] bd 04 [2] a6 02 [2] ba 05 [2] a6 2a }

  condition:
    any of them
}