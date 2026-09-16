rule TTP_XOR_MULT_DOSStub_4bcc {
  strings:
    $key_4bcc = { 1f a4 [2] 6b bc [2] 2c be [2] 6b af [2] 25 a3 [2] 29 a9 [2] 3e a2 [2] 25 ec [2] 18 }

  condition:
    any of them
}