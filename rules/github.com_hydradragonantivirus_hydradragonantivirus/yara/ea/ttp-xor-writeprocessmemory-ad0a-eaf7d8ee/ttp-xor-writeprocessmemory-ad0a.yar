rule TTP_XOR_WriteProcessMemory_ad0a {
  strings:
    $key_ad0a = { fa 78 [2] c8 5a [2] ce 6f [2] e0 6f [2] df 73 }

  condition:
    any of them
}