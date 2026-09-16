rule TTP_XOR_WriteProcessMemory_baf9 {
  strings:
    $key_baf9 = { ed 8b [2] df a9 [2] d9 9c [2] f7 9c [2] c8 80 }

  condition:
    any of them
}