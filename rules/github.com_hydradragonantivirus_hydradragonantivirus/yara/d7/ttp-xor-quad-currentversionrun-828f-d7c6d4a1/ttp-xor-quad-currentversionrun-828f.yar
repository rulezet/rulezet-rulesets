rule TTP_XOR_QUAD_CurrentVersionRun_828f {
  strings:
    $key_828f = { d1 e0 [2] f5 ee [2] de c2 [2] f0 e0 [2] e4 fb [2] eb e1 [2] f5 fc [2] f7 fd [2] ec fb [2] f0 fc [2] ec d3 }

  condition:
    any of them
}