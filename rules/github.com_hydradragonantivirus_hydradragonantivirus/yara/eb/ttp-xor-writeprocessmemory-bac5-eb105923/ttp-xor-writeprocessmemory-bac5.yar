rule TTP_XOR_WriteProcessMemory_bac5 {
  strings:
    $key_bac5 = { ed b7 [2] df 95 [2] d9 a0 [2] f7 a0 [2] c8 bc }

  condition:
    any of them
}