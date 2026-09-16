rule TTP_XOR_MULT_DOSStub_dddc {
  strings:
    $key_dddc = { 89 b4 [2] fd ac [2] ba ae [2] fd bf [2] b3 b3 [2] bf b9 [2] a8 b2 [2] b3 fc [2] 8e }

  condition:
    any of them
}