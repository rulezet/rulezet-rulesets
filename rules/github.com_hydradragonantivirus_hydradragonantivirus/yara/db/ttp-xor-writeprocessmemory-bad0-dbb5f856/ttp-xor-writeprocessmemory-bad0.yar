rule TTP_XOR_WriteProcessMemory_bad0 {
  strings:
    $key_bad0 = { ed a2 [2] df 80 [2] d9 b5 [2] f7 b5 [2] c8 a9 }

  condition:
    any of them
}