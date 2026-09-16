rule TTP_XOR_QUAD_CurrentVersionRun_921c {
  strings:
    $key_921c = { c1 73 [2] e5 7d [2] ce 51 [2] e0 73 [2] f4 68 [2] fb 72 [2] e5 6f [2] e7 6e [2] fc 68 [2] e0 6f [2] fc 40 }

  condition:
    any of them
}