rule TTP_XOR_QUAD_CurrentVersionRun_dbb6 {
  strings:
    $key_dbb6 = { 88 d9 [2] ac d7 [2] 87 fb [2] a9 d9 [2] bd c2 [2] b2 d8 [2] ac c5 [2] ae c4 [2] b5 c2 [2] a9 c5 [2] b5 ea }

  condition:
    any of them
}