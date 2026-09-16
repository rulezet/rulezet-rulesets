rule TTP_XOR_MULT_DOSStub_1bcc {
  strings:
    $key_1bcc = { 4f a4 [2] 3b bc [2] 7c be [2] 3b af [2] 75 a3 [2] 79 a9 [2] 6e a2 [2] 75 ec [2] 48 }

  condition:
    any of them
}