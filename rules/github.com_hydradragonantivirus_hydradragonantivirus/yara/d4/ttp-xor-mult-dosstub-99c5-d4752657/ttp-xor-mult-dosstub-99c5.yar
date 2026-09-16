rule TTP_XOR_MULT_DOSStub_99c5 {
  strings:
    $key_99c5 = { cd ad [2] b9 b5 [2] fe b7 [2] b9 a6 [2] f7 aa [2] fb a0 [2] ec ab [2] f7 e5 [2] ca }

  condition:
    any of them
}