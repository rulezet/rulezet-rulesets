rule TTP_XOR_MULT_DOSStub_6bcc {
  strings:
    $key_6bcc = { 3f a4 [2] 4b bc [2] 0c be [2] 4b af [2] 05 a3 [2] 09 a9 [2] 1e a2 [2] 05 ec [2] 38 }

  condition:
    any of them
}