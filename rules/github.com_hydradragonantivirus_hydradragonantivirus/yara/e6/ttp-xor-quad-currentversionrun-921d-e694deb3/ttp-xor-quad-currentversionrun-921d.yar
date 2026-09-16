rule TTP_XOR_QUAD_CurrentVersionRun_921d {
  strings:
    $key_921d = { c1 72 [2] e5 7c [2] ce 50 [2] e0 72 [2] f4 69 [2] fb 73 [2] e5 6e [2] e7 6f [2] fc 69 [2] e0 6e [2] fc 41 }

  condition:
    any of them
}