rule TTP_XOR_QUAD_CurrentVersionRun_b98a {
  strings:
    $key_b98a = { ea e5 [2] ce eb [2] e5 c7 [2] cb e5 [2] df fe [2] d0 e4 [2] ce f9 [2] cc f8 [2] d7 fe [2] cb f9 [2] d7 d6 }

  condition:
    any of them
}