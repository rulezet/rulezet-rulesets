rule TTP_XOR_WriteProcessMemory_ad25 {
  strings:
    $key_ad25 = { fa 57 [2] c8 75 [2] ce 40 [2] e0 40 [2] df 5c }

  condition:
    any of them
}