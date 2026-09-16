rule TTP_XOR_WriteProcessMemory_ad3a {
  strings:
    $key_ad3a = { fa 48 [2] c8 6a [2] ce 5f [2] e0 5f [2] df 43 }

  condition:
    any of them
}