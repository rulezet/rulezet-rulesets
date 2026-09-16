rule TTP_XOR_WriteProcessMemory_ad5a {
  strings:
    $key_ad5a = { fa 28 [2] c8 0a [2] ce 3f [2] e0 3f [2] df 23 }

  condition:
    any of them
}