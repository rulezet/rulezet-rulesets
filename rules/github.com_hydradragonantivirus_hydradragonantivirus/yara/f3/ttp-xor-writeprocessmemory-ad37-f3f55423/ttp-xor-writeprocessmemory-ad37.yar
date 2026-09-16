rule TTP_XOR_WriteProcessMemory_ad37 {
  strings:
    $key_ad37 = { fa 45 [2] c8 67 [2] ce 52 [2] e0 52 [2] df 4e }

  condition:
    any of them
}