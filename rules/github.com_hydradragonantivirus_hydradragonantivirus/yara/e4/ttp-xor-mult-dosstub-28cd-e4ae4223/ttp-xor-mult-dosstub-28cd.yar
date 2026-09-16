rule TTP_XOR_MULT_DOSStub_28cd {
  strings:
    $key_28cd = { 7c a5 [2] 08 bd [2] 4f bf [2] 08 ae [2] 46 a2 [2] 4a a8 [2] 5d a3 [2] 46 ed [2] 7b }

  condition:
    any of them
}