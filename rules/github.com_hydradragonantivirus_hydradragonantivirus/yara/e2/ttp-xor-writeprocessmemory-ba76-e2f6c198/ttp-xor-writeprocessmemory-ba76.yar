rule TTP_XOR_WriteProcessMemory_ba76 {
  strings:
    $key_ba76 = { ed 04 [2] df 26 [2] d9 13 [2] f7 13 [2] c8 0f }

  condition:
    any of them
}