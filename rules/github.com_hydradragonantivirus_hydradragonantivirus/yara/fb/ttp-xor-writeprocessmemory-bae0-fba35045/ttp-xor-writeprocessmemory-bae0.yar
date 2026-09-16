rule TTP_XOR_WriteProcessMemory_bae0 {
  strings:
    $key_bae0 = { ed 92 [2] df b0 [2] d9 85 [2] f7 85 [2] c8 99 }

  condition:
    any of them
}