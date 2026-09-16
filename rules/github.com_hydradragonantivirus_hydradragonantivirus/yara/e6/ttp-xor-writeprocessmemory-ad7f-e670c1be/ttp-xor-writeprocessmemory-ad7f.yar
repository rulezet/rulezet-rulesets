rule TTP_XOR_WriteProcessMemory_ad7f {
  strings:
    $key_ad7f = { fa 0d [2] c8 2f [2] ce 1a [2] e0 1a [2] df 06 }

  condition:
    any of them
}