rule TTP_XOR_WriteProcessMemory_ad6a {
  strings:
    $key_ad6a = { fa 18 [2] c8 3a [2] ce 0f [2] e0 0f [2] df 13 }

  condition:
    any of them
}