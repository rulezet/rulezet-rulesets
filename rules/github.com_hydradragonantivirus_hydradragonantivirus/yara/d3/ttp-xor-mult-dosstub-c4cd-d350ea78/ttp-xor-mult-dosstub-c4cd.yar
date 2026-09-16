rule TTP_XOR_MULT_DOSStub_c4cd {
  strings:
    $key_c4cd = { 90 a5 [2] e4 bd [2] a3 bf [2] e4 ae [2] aa a2 [2] a6 a8 [2] b1 a3 [2] aa ed [2] 97 }

  condition:
    any of them
}