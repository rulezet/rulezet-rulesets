rule TTP_XOR_MULT_DOSStub_d900 {
  strings:
    $key_d900 = { 8d 68 [2] f9 70 [2] be 72 [2] f9 63 [2] b7 6f [2] bb 65 [2] ac 6e [2] b7 20 [2] 8a }

  condition:
    any of them
}