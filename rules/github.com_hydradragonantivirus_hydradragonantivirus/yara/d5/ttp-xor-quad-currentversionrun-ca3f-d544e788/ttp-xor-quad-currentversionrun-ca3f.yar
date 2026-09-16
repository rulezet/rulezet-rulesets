rule TTP_XOR_QUAD_CurrentVersionRun_ca3f {
  strings:
    $key_ca3f = { 99 50 [2] bd 5e [2] 96 72 [2] b8 50 [2] ac 4b [2] a3 51 [2] bd 4c [2] bf 4d [2] a4 4b [2] b8 4c [2] a4 63 }

  condition:
    any of them
}