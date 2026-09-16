rule TTP_XOR_MULT_DOSStub_cb0f {
  strings:
    $key_cb0f = { 9f 67 [2] eb 7f [2] ac 7d [2] eb 6c [2] a5 60 [2] a9 6a [2] be 61 [2] a5 2f [2] 98 }

  condition:
    any of them
}