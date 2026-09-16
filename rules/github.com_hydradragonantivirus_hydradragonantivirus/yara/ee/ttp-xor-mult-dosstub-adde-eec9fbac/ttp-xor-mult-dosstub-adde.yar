rule TTP_XOR_MULT_DOSStub_adde {
  strings:
    $key_adde = { f9 b6 [2] 8d ae [2] ca ac [2] 8d bd [2] c3 b1 [2] cf bb [2] d8 b0 [2] c3 fe [2] fe }

  condition:
    any of them
}