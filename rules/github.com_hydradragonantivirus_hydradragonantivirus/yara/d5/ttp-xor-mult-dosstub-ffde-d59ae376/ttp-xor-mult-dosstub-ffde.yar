rule TTP_XOR_MULT_DOSStub_ffde {
  strings:
    $key_ffde = { ab b6 [2] df ae [2] 98 ac [2] df bd [2] 91 b1 [2] 9d bb [2] 8a b0 [2] 91 fe [2] ac }

  condition:
    any of them
}