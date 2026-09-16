rule TTP_XOR_WriteProcessMemory_ad6e {
  strings:
    $key_ad6e = { fa 1c [2] c8 3e [2] ce 0b [2] e0 0b [2] df 17 }

  condition:
    any of them
}