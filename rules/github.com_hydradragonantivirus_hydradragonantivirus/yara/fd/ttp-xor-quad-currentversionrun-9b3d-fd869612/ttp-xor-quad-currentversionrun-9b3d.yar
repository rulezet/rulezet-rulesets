rule TTP_XOR_QUAD_CurrentVersionRun_9b3d {
  strings:
    $key_9b3d = { c8 52 [2] ec 5c [2] c7 70 [2] e9 52 [2] fd 49 [2] f2 53 [2] ec 4e [2] ee 4f [2] f5 49 [2] e9 4e [2] f5 61 }

  condition:
    any of them
}