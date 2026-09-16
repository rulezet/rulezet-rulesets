rule TTP_XOR_MULT_DOSStub_f6cf {
  strings:
    $key_f6cf = { a2 a7 [2] d6 bf [2] 91 bd [2] d6 ac [2] 98 a0 [2] 94 aa [2] 83 a1 [2] 98 ef [2] a5 }

  condition:
    any of them
}