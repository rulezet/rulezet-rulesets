rule TTP_XOR_WriteProcessMemory_bae7 {
  strings:
    $key_bae7 = { ed 95 [2] df b7 [2] d9 82 [2] f7 82 [2] c8 9e }

  condition:
    any of them
}