rule TTP_XOR_QUAD_CurrentVersionRun_82e3 {
  strings:
    $key_82e3 = { d1 8c [2] f5 82 [2] de ae [2] f0 8c [2] e4 97 [2] eb 8d [2] f5 90 [2] f7 91 [2] ec 97 [2] f0 90 [2] ec bf }

  condition:
    any of them
}