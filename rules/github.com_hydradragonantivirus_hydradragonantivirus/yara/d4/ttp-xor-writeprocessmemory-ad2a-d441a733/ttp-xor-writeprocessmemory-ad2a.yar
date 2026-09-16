rule TTP_XOR_WriteProcessMemory_ad2a {
  strings:
    $key_ad2a = { fa 58 [2] c8 7a [2] ce 4f [2] e0 4f [2] df 53 }

  condition:
    any of them
}