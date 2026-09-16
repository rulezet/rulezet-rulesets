rule TTP_XOR_MULT_DOSStub_f3ce {
  strings:
    $key_f3ce = { a7 a6 [2] d3 be [2] 94 bc [2] d3 ad [2] 9d a1 [2] 91 ab [2] 86 a0 [2] 9d ee [2] a0 }

  condition:
    any of them
}