rule TTP_XOR_MULT_DOSStub_0dc9 {
  strings:
    $key_0dc9 = { 59 a1 [2] 2d b9 [2] 6a bb [2] 2d aa [2] 63 a6 [2] 6f ac [2] 78 a7 [2] 63 e9 [2] 5e }

  condition:
    any of them
}