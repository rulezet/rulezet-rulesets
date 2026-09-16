rule TTP_XOR_QUAD_CurrentVersionRun_993c {
  strings:
    $key_993c = { ca 53 [2] ee 5d [2] c5 71 [2] eb 53 [2] ff 48 [2] f0 52 [2] ee 4f [2] ec 4e [2] f7 48 [2] eb 4f [2] f7 60 }

  condition:
    any of them
}