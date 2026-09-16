rule TTP_XOR_MULT_DOSStub_af80 {
  strings:
    $key_af80 = { fb e8 [2] 8f f0 [2] c8 f2 [2] 8f e3 [2] c1 ef [2] cd e5 [2] da ee [2] c1 a0 [2] fc }

  condition:
    any of them
}