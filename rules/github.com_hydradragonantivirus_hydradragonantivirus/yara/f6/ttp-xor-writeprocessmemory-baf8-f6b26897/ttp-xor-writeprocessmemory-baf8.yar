rule TTP_XOR_WriteProcessMemory_baf8 {
  strings:
    $key_baf8 = { ed 8a [2] df a8 [2] d9 9d [2] f7 9d [2] c8 81 }

  condition:
    any of them
}