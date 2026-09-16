rule TTP_XOR_WriteProcessMemory_adb7 {
  strings:
    $key_adb7 = { fa c5 [2] c8 e7 [2] ce d2 [2] e0 d2 [2] df ce }

  condition:
    any of them
}