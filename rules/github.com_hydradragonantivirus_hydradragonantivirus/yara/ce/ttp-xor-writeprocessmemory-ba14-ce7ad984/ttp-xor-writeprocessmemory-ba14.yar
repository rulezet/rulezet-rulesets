rule TTP_XOR_WriteProcessMemory_ba14 {
  strings:
    $key_ba14 = { ed 66 [2] df 44 [2] d9 71 [2] f7 71 [2] c8 6d }

  condition:
    any of them
}