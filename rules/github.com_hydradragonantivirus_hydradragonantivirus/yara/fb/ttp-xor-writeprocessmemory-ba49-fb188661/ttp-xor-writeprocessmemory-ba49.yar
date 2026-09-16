rule TTP_XOR_WriteProcessMemory_ba49 {
  strings:
    $key_ba49 = { ed 3b [2] df 19 [2] d9 2c [2] f7 2c [2] c8 30 }

  condition:
    any of them
}