rule TTP_XOR_WriteProcessMemory_bad4 {
  strings:
    $key_bad4 = { ed a6 [2] df 84 [2] d9 b1 [2] f7 b1 [2] c8 ad }

  condition:
    any of them
}