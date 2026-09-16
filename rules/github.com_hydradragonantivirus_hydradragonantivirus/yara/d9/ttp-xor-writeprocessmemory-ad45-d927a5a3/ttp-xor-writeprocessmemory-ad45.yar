rule TTP_XOR_WriteProcessMemory_ad45 {
  strings:
    $key_ad45 = { fa 37 [2] c8 15 [2] ce 20 [2] e0 20 [2] df 3c }

  condition:
    any of them
}