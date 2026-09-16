rule TTP_XOR_QUAD_CurrentVersionRun_8217 {
  strings:
    $key_8217 = { d1 78 [2] f5 76 [2] de 5a [2] f0 78 [2] e4 63 [2] eb 79 [2] f5 64 [2] f7 65 [2] ec 63 [2] f0 64 [2] ec 4b }

  condition:
    any of them
}