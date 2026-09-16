rule TTP_XOR_MULT_DOSStub_8abd {
  strings:
    $key_8abd = { de d5 [2] aa cd [2] ed cf [2] aa de [2] e4 d2 [2] e8 d8 [2] ff d3 [2] e4 9d [2] d9 }

  condition:
    any of them
}