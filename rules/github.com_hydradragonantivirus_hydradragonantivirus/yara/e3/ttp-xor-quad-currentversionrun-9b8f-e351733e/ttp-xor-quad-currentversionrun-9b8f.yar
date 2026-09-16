rule TTP_XOR_QUAD_CurrentVersionRun_9b8f {
  strings:
    $key_9b8f = { c8 e0 [2] ec ee [2] c7 c2 [2] e9 e0 [2] fd fb [2] f2 e1 [2] ec fc [2] ee fd [2] f5 fb [2] e9 fc [2] f5 d3 }

  condition:
    any of them
}