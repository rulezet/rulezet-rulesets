rule TTP_XOR_QUAD_CurrentVersionRun_b99c {
  strings:
    $key_b99c = { ea f3 [2] ce fd [2] e5 d1 [2] cb f3 [2] df e8 [2] d0 f2 [2] ce ef [2] cc ee [2] d7 e8 [2] cb ef [2] d7 c0 }

  condition:
    any of them
}