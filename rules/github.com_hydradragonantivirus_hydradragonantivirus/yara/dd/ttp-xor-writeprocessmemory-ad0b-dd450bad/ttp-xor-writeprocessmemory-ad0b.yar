rule TTP_XOR_WriteProcessMemory_ad0b {
  strings:
    $key_ad0b = { fa 79 [2] c8 5b [2] ce 6e [2] e0 6e [2] df 72 }

  condition:
    any of them
}