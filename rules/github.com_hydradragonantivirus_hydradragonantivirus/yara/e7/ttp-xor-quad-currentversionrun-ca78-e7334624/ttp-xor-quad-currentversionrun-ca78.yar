rule TTP_XOR_QUAD_CurrentVersionRun_ca78 {
  strings:
    $key_ca78 = { 99 17 [2] bd 19 [2] 96 35 [2] b8 17 [2] ac 0c [2] a3 16 [2] bd 0b [2] bf 0a [2] a4 0c [2] b8 0b [2] a4 24 }

  condition:
    any of them
}