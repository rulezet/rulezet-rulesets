rule TTP_XOR_QUAD_CurrentVersionRun_993e {
  strings:
    $key_993e = { ca 51 [2] ee 5f [2] c5 73 [2] eb 51 [2] ff 4a [2] f0 50 [2] ee 4d [2] ec 4c [2] f7 4a [2] eb 4d [2] f7 62 }

  condition:
    any of them
}