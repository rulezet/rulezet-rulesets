rule TTP_XOR_MULT_DOSStub_fbbf {
  strings:
    $key_fbbf = { af d7 [2] db cf [2] 9c cd [2] db dc [2] 95 d0 [2] 99 da [2] 8e d1 [2] 95 9f [2] a8 }

  condition:
    any of them
}