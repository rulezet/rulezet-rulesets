rule TTP_XOR_MULT_DOSStub_2bc5 {
  strings:
    $key_2bc5 = { 7f ad [2] 0b b5 [2] 4c b7 [2] 0b a6 [2] 45 aa [2] 49 a0 [2] 5e ab [2] 45 e5 [2] 78 }

  condition:
    any of them
}