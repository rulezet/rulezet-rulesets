rule TTP_XOR_WriteProcessMemory_ba91 {
  strings:
    $key_ba91 = { ed e3 [2] df c1 [2] d9 f4 [2] f7 f4 [2] c8 e8 }

  condition:
    any of them
}