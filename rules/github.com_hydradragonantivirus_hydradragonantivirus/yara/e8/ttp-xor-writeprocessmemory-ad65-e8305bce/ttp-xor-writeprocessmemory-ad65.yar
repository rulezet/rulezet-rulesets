rule TTP_XOR_WriteProcessMemory_ad65 {
  strings:
    $key_ad65 = { fa 17 [2] c8 35 [2] ce 00 [2] e0 00 [2] df 1c }

  condition:
    any of them
}