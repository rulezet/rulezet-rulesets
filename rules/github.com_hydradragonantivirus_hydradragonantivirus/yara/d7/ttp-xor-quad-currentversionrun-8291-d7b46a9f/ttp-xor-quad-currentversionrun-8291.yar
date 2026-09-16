rule TTP_XOR_QUAD_CurrentVersionRun_8291 {
  strings:
    $key_8291 = { d1 fe [2] f5 f0 [2] de dc [2] f0 fe [2] e4 e5 [2] eb ff [2] f5 e2 [2] f7 e3 [2] ec e5 [2] f0 e2 [2] ec cd }

  condition:
    any of them
}