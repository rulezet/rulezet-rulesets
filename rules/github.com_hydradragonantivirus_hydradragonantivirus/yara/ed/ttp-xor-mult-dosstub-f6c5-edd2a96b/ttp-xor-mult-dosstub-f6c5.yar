rule TTP_XOR_MULT_DOSStub_f6c5 {
  strings:
    $key_f6c5 = { a2 ad [2] d6 b5 [2] 91 b7 [2] d6 a6 [2] 98 aa [2] 94 a0 [2] 83 ab [2] 98 e5 [2] a5 }

  condition:
    any of them
}