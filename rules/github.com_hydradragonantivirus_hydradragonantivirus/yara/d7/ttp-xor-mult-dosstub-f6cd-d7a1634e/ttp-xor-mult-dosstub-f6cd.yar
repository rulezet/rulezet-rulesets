rule TTP_XOR_MULT_DOSStub_f6cd {
  strings:
    $key_f6cd = { a2 a5 [2] d6 bd [2] 91 bf [2] d6 ae [2] 98 a2 [2] 94 a8 [2] 83 a3 [2] 98 ed [2] a5 }

  condition:
    any of them
}