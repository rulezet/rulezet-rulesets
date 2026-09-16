rule TTP_XOR_MULT_DOSStub_29da {
  strings:
    $key_29da = { 7d b2 [2] 09 aa [2] 4e a8 [2] 09 b9 [2] 47 b5 [2] 4b bf [2] 5c b4 [2] 47 fa [2] 7a }

  condition:
    any of them
}