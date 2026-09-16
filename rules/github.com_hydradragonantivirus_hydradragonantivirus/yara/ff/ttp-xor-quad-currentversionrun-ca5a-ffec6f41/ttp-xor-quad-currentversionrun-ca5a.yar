rule TTP_XOR_QUAD_CurrentVersionRun_ca5a {
  strings:
    $key_ca5a = { 99 35 [2] bd 3b [2] 96 17 [2] b8 35 [2] ac 2e [2] a3 34 [2] bd 29 [2] bf 28 [2] a4 2e [2] b8 29 [2] a4 06 }

  condition:
    any of them
}