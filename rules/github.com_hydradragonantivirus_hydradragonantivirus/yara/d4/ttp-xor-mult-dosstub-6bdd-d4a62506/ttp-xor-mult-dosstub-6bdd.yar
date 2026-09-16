rule TTP_XOR_MULT_DOSStub_6bdd {
  strings:
    $key_6bdd = { 3f b5 [2] 4b ad [2] 0c af [2] 4b be [2] 05 b2 [2] 09 b8 [2] 1e b3 [2] 05 fd [2] 38 }

  condition:
    any of them
}