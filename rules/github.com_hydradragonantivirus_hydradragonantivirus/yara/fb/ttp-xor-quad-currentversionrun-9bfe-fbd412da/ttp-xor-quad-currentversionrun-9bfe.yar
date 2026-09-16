rule TTP_XOR_QUAD_CurrentVersionRun_9bfe {
  strings:
    $key_9bfe = { c8 91 [2] ec 9f [2] c7 b3 [2] e9 91 [2] fd 8a [2] f2 90 [2] ec 8d [2] ee 8c [2] f5 8a [2] e9 8d [2] f5 a2 }

  condition:
    any of them
}