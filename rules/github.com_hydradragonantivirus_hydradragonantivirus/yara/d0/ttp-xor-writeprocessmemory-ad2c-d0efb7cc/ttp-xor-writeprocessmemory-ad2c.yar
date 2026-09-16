rule TTP_XOR_WriteProcessMemory_ad2c {
  strings:
    $key_ad2c = { fa 5e [2] c8 7c [2] ce 49 [2] e0 49 [2] df 55 }

  condition:
    any of them
}