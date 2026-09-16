rule TTP_XOR_QUAD_CurrentVersionRun_ca04 {
  strings:
    $key_ca04 = { 99 6b [2] bd 65 [2] 96 49 [2] b8 6b [2] ac 70 [2] a3 6a [2] bd 77 [2] bf 76 [2] a4 70 [2] b8 77 [2] a4 58 }

  condition:
    any of them
}