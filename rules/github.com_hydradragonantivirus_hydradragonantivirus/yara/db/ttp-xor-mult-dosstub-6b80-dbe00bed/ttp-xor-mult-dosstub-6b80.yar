rule TTP_XOR_MULT_DOSStub_6b80 {
  strings:
    $key_6b80 = { 3f e8 [2] 4b f0 [2] 0c f2 [2] 4b e3 [2] 05 ef [2] 09 e5 [2] 1e ee [2] 05 a0 [2] 38 }

  condition:
    any of them
}