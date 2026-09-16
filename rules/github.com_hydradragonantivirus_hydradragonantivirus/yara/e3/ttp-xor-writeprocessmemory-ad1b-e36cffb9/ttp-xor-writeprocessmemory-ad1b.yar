rule TTP_XOR_WriteProcessMemory_ad1b {
  strings:
    $key_ad1b = { fa 69 [2] c8 4b [2] ce 7e [2] e0 7e [2] df 62 }

  condition:
    any of them
}