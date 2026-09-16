rule TTP_XOR_MULT_DOSStub_b9bf {
  strings:
    $key_b9bf = { ed d7 [2] 99 cf [2] de cd [2] 99 dc [2] d7 d0 [2] db da [2] cc d1 [2] d7 9f [2] ea }

  condition:
    any of them
}