rule TTP_XOR_WriteProcessMemory_ad2e {
  strings:
    $key_ad2e = { fa 5c [2] c8 7e [2] ce 4b [2] e0 4b [2] df 57 }

  condition:
    any of them
}