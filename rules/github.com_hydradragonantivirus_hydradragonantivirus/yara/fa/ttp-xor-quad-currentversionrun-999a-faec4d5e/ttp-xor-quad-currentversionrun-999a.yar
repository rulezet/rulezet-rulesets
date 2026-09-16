rule TTP_XOR_QUAD_CurrentVersionRun_999a {
  strings:
    $key_999a = { ca f5 [2] ee fb [2] c5 d7 [2] eb f5 [2] ff ee [2] f0 f4 [2] ee e9 [2] ec e8 [2] f7 ee [2] eb e9 [2] f7 c6 }

  condition:
    any of them
}