rule TTP_XOR_QUAD_CurrentVersionRun_d368 {
  strings:
    $key_d368 = { 80 07 [2] a4 09 [2] 8f 25 [2] a1 07 [2] b5 1c [2] ba 06 [2] a4 1b [2] a6 1a [2] bd 1c [2] a1 1b [2] bd 34 }

  condition:
    any of them
}