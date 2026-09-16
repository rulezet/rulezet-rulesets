rule TTP_XOR_MULT_DOSStub_5bcc {
  strings:
    $key_5bcc = { 0f a4 [2] 7b bc [2] 3c be [2] 7b af [2] 35 a3 [2] 39 a9 [2] 2e a2 [2] 35 ec [2] 08 }

  condition:
    any of them
}