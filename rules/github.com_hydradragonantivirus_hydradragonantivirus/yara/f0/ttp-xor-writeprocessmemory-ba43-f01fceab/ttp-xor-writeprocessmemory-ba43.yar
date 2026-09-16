rule TTP_XOR_WriteProcessMemory_ba43 {
  strings:
    $key_ba43 = { ed 31 [2] df 13 [2] d9 26 [2] f7 26 [2] c8 3a }

  condition:
    any of them
}