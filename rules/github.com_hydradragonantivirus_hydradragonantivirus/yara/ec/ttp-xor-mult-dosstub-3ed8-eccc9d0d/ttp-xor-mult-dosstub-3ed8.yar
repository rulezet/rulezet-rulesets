rule TTP_XOR_MULT_DOSStub_3ed8 {
  strings:
    $key_3ed8 = { 6a b0 [2] 1e a8 [2] 59 aa [2] 1e bb [2] 50 b7 [2] 5c bd [2] 4b b6 [2] 50 f8 [2] 6d }

  condition:
    any of them
}