rule TTP_XOR_MULT_DOSStub_3b9c {
  strings:
    $key_3b9c = { 6f f4 [2] 1b ec [2] 5c ee [2] 1b ff [2] 55 f3 [2] 59 f9 [2] 4e f2 [2] 55 bc [2] 68 }

  condition:
    any of them
}