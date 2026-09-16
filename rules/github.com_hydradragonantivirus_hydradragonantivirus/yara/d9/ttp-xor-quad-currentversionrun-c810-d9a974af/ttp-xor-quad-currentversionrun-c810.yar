rule TTP_XOR_QUAD_CurrentVersionRun_c810 {
  strings:
    $key_c810 = { 9b 7f [2] bf 71 [2] 94 5d [2] ba 7f [2] ae 64 [2] a1 7e [2] bf 63 [2] bd 62 [2] a6 64 [2] ba 63 [2] a6 4c }

  condition:
    any of them
}