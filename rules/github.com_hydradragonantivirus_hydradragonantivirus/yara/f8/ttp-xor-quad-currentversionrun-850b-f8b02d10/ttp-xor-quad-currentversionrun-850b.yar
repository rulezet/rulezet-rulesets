rule TTP_XOR_QUAD_CurrentVersionRun_850b {
  strings:
    $key_850b = { d6 64 [2] f2 6a [2] d9 46 [2] f7 64 [2] e3 7f [2] ec 65 [2] f2 78 [2] f0 79 [2] eb 7f [2] f7 78 [2] eb 57 }

  condition:
    any of them
}