rule TTP_XOR_WriteProcessMemory_bafb {
  strings:
    $key_bafb = { ed 89 [2] df ab [2] d9 9e [2] f7 9e [2] c8 82 }

  condition:
    any of them
}