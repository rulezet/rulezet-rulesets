rule TTP_XOR_QUAD_CurrentVersionRun_9910 {
  strings:
    $key_9910 = { ca 7f [2] ee 71 [2] c5 5d [2] eb 7f [2] ff 64 [2] f0 7e [2] ee 63 [2] ec 62 [2] f7 64 [2] eb 63 [2] f7 4c }

  condition:
    any of them
}