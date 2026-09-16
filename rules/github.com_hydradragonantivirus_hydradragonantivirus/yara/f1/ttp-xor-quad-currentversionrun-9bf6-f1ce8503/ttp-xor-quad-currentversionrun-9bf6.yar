rule TTP_XOR_QUAD_CurrentVersionRun_9bf6 {
  strings:
    $key_9bf6 = { c8 99 [2] ec 97 [2] c7 bb [2] e9 99 [2] fd 82 [2] f2 98 [2] ec 85 [2] ee 84 [2] f5 82 [2] e9 85 [2] f5 aa }

  condition:
    any of them
}