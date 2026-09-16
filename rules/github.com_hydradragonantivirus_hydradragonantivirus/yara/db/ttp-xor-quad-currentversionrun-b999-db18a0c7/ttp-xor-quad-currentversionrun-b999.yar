rule TTP_XOR_QUAD_CurrentVersionRun_b999 {
  strings:
    $key_b999 = { ea f6 [2] ce f8 [2] e5 d4 [2] cb f6 [2] df ed [2] d0 f7 [2] ce ea [2] cc eb [2] d7 ed [2] cb ea [2] d7 c5 }

  condition:
    any of them
}