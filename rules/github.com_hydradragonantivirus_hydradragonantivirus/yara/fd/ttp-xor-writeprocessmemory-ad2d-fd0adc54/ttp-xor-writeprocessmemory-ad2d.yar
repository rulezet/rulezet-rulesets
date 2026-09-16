rule TTP_XOR_WriteProcessMemory_ad2d {
  strings:
    $key_ad2d = { fa 5f [2] c8 7d [2] ce 48 [2] e0 48 [2] df 54 }

  condition:
    any of them
}