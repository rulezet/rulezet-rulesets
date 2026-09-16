rule TTP_XOR_WriteProcessMemory_baf7 {
  strings:
    $key_baf7 = { ed 85 [2] df a7 [2] d9 92 [2] f7 92 [2] c8 8e }

  condition:
    any of them
}