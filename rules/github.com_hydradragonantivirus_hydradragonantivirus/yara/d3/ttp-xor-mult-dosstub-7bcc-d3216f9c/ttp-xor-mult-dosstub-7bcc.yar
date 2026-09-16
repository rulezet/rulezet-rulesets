rule TTP_XOR_MULT_DOSStub_7bcc {
  strings:
    $key_7bcc = { 2f a4 [2] 5b bc [2] 1c be [2] 5b af [2] 15 a3 [2] 19 a9 [2] 0e a2 [2] 15 ec [2] 28 }

  condition:
    any of them
}