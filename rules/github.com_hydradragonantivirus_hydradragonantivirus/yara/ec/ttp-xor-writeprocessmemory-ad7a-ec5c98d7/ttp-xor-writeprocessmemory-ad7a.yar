rule TTP_XOR_WriteProcessMemory_ad7a {
  strings:
    $key_ad7a = { fa 08 [2] c8 2a [2] ce 1f [2] e0 1f [2] df 03 }

  condition:
    any of them
}