rule TTP_XOR_QUAD_CurrentVersionRun_9649 {
  strings:
    $key_9649 = { c5 26 [2] e1 28 [2] ca 04 [2] e4 26 [2] f0 3d [2] ff 27 [2] e1 3a [2] e3 3b [2] f8 3d [2] e4 3a [2] f8 15 }

  condition:
    any of them
}