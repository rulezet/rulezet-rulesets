rule TTP_XOR_MULT_DOSStub_2bcc {
  strings:
    $key_2bcc = { 7f a4 [2] 0b bc [2] 4c be [2] 0b af [2] 45 a3 [2] 49 a9 [2] 5e a2 [2] 45 ec [2] 78 }

  condition:
    any of them
}