rule TTP_XOR_MULT_DOSStub_93cf {
  strings:
    $key_93cf = { c7 a7 [2] b3 bf [2] f4 bd [2] b3 ac [2] fd a0 [2] f1 aa [2] e6 a1 [2] fd ef [2] c0 }

  condition:
    any of them
}