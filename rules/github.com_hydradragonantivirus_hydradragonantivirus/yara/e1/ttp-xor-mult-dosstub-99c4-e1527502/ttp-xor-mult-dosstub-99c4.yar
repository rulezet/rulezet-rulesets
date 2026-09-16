rule TTP_XOR_MULT_DOSStub_99c4 {
  strings:
    $key_99c4 = { cd ac [2] b9 b4 [2] fe b6 [2] b9 a7 [2] f7 ab [2] fb a1 [2] ec aa [2] f7 e4 [2] ca }

  condition:
    any of them
}