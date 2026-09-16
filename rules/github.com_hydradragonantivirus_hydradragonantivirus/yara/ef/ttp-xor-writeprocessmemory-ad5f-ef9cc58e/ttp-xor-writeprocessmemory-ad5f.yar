rule TTP_XOR_WriteProcessMemory_ad5f {
  strings:
    $key_ad5f = { fa 2d [2] c8 0f [2] ce 3a [2] e0 3a [2] df 26 }

  condition:
    any of them
}