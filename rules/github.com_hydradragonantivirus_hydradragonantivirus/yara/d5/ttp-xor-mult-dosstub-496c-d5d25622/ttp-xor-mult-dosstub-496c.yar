rule TTP_XOR_MULT_DOSStub_496c {
  strings:
    $key_496c = { 1d 04 [2] 69 1c [2] 2e 1e [2] 69 0f [2] 27 03 [2] 2b 09 [2] 3c 02 [2] 27 4c [2] 1a }

  condition:
    any of them
}