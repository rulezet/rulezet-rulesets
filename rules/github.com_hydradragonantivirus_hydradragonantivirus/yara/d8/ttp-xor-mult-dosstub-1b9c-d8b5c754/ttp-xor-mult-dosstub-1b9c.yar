rule TTP_XOR_MULT_DOSStub_1b9c {
  strings:
    $key_1b9c = { 4f f4 [2] 3b ec [2] 7c ee [2] 3b ff [2] 75 f3 [2] 79 f9 [2] 6e f2 [2] 75 bc [2] 48 }

  condition:
    any of them
}