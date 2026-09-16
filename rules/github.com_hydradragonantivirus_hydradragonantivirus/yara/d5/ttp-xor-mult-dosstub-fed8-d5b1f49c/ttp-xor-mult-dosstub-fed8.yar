rule TTP_XOR_MULT_DOSStub_fed8 {
  strings:
    $key_fed8 = { aa b0 [2] de a8 [2] 99 aa [2] de bb [2] 90 b7 [2] 9c bd [2] 8b b6 [2] 90 f8 [2] ad }

  condition:
    any of them
}