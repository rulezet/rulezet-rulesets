rule TTP_XOR_WriteProcessMemory_baf1 {
  strings:
    $key_baf1 = { ed 83 [2] df a1 [2] d9 94 [2] f7 94 [2] c8 88 }

  condition:
    any of them
}