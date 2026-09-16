rule TTP_XOR_MULT_DOSStub_8ada {
  strings:
    $key_8ada = { de b2 [2] aa aa [2] ed a8 [2] aa b9 [2] e4 b5 [2] e8 bf [2] ff b4 [2] e4 fa [2] d9 }

  condition:
    any of them
}