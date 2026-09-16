rule TTP_XOR_MULT_DOSStub_7bdd {
  strings:
    $key_7bdd = { 2f b5 [2] 5b ad [2] 1c af [2] 5b be [2] 15 b2 [2] 19 b8 [2] 0e b3 [2] 15 fd [2] 28 }

  condition:
    any of them
}