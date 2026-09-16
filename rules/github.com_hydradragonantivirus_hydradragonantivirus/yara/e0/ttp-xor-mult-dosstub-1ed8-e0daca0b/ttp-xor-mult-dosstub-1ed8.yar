rule TTP_XOR_MULT_DOSStub_1ed8 {
  strings:
    $key_1ed8 = { 4a b0 [2] 3e a8 [2] 79 aa [2] 3e bb [2] 70 b7 [2] 7c bd [2] 6b b6 [2] 70 f8 [2] 4d }

  condition:
    any of them
}