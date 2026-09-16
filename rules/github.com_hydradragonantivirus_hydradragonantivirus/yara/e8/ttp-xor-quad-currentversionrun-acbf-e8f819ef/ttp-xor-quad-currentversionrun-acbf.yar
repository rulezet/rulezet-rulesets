rule TTP_XOR_QUAD_CurrentVersionRun_acbf {
  strings:
    $key_acbf = { ff d0 [2] db de [2] f0 f2 [2] de d0 [2] ca cb [2] c5 d1 [2] db cc [2] d9 cd [2] c2 cb [2] de cc [2] c2 e3 }

  condition:
    any of them
}