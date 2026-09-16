rule TTP_XOR_MULT_DOSStub_f6bf {
  strings:
    $key_f6bf = { a2 d7 [2] d6 cf [2] 91 cd [2] d6 dc [2] 98 d0 [2] 94 da [2] 83 d1 [2] 98 9f [2] a5 }

  condition:
    any of them
}