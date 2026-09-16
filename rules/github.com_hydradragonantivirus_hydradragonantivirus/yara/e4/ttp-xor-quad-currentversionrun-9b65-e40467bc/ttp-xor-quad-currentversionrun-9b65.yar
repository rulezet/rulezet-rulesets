rule TTP_XOR_QUAD_CurrentVersionRun_9b65 {
  strings:
    $key_9b65 = { c8 0a [2] ec 04 [2] c7 28 [2] e9 0a [2] fd 11 [2] f2 0b [2] ec 16 [2] ee 17 [2] f5 11 [2] e9 16 [2] f5 39 }

  condition:
    any of them
}