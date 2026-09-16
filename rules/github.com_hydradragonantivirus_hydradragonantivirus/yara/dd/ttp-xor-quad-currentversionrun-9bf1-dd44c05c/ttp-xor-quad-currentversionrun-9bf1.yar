rule TTP_XOR_QUAD_CurrentVersionRun_9bf1 {
  strings:
    $key_9bf1 = { c8 9e [2] ec 90 [2] c7 bc [2] e9 9e [2] fd 85 [2] f2 9f [2] ec 82 [2] ee 83 [2] f5 85 [2] e9 82 [2] f5 ad }

  condition:
    any of them
}