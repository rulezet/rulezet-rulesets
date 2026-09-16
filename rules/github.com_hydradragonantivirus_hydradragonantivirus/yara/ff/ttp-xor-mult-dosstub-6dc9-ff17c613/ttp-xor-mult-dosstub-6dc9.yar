rule TTP_XOR_MULT_DOSStub_6dc9 {
  strings:
    $key_6dc9 = { 39 a1 [2] 4d b9 [2] 0a bb [2] 4d aa [2] 03 a6 [2] 0f ac [2] 18 a7 [2] 03 e9 [2] 3e }

  condition:
    any of them
}