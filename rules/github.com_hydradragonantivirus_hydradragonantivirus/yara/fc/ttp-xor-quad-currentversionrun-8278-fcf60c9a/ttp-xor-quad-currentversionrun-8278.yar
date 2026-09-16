rule TTP_XOR_QUAD_CurrentVersionRun_8278 {
  strings:
    $key_8278 = { d1 17 [2] f5 19 [2] de 35 [2] f0 17 [2] e4 0c [2] eb 16 [2] f5 0b [2] f7 0a [2] ec 0c [2] f0 0b [2] ec 24 }

  condition:
    any of them
}