rule TTP_XOR_MULT_DOSStub_a880 {
  strings:
    $key_a880 = { fc e8 [2] 88 f0 [2] cf f2 [2] 88 e3 [2] c6 ef [2] ca e5 [2] dd ee [2] c6 a0 [2] fb }

  condition:
    any of them
}