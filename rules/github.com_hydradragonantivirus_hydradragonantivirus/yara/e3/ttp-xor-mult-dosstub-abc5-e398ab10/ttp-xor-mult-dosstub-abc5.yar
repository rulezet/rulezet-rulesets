rule TTP_XOR_MULT_DOSStub_abc5 {
  strings:
    $key_abc5 = { ff ad [2] 8b b5 [2] cc b7 [2] 8b a6 [2] c5 aa [2] c9 a0 [2] de ab [2] c5 e5 [2] f8 }

  condition:
    any of them
}