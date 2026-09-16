rule TTP_XOR_MULT_DOSStub_ff82 {
  strings:
    $key_ff82 = { ab ea [2] df f2 [2] 98 f0 [2] df e1 [2] 91 ed [2] 9d e7 [2] 8a ec [2] 91 a2 [2] ac }

  condition:
    any of them
}