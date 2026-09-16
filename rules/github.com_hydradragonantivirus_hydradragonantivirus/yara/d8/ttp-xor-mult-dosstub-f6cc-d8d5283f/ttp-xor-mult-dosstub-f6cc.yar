rule TTP_XOR_MULT_DOSStub_f6cc {
  strings:
    $key_f6cc = { a2 a4 [2] d6 bc [2] 91 be [2] d6 af [2] 98 a3 [2] 94 a9 [2] 83 a2 [2] 98 ec [2] a5 }

  condition:
    any of them
}