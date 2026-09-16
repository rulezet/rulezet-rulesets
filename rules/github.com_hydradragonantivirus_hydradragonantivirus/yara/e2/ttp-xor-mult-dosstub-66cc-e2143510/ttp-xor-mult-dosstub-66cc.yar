rule TTP_XOR_MULT_DOSStub_66cc {
  strings:
    $key_66cc = { 32 a4 [2] 46 bc [2] 01 be [2] 46 af [2] 08 a3 [2] 04 a9 [2] 13 a2 [2] 08 ec [2] 35 }

  condition:
    any of them
}