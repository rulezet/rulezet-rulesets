rule TTP_XOR_WriteProcessMemory_bad2 {
  strings:
    $key_bad2 = { ed a0 [2] df 82 [2] d9 b7 [2] f7 b7 [2] c8 ab }

  condition:
    any of them
}