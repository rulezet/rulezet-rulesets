rule TTP_XOR_WriteProcessMemory_ba84 {
  strings:
    $key_ba84 = { ed f6 [2] df d4 [2] d9 e1 [2] f7 e1 [2] c8 fd }

  condition:
    any of them
}