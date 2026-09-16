rule TTP_XOR_WriteProcessMemory_baf0 {
  strings:
    $key_baf0 = { ed 82 [2] df a0 [2] d9 95 [2] f7 95 [2] c8 89 }

  condition:
    any of them
}