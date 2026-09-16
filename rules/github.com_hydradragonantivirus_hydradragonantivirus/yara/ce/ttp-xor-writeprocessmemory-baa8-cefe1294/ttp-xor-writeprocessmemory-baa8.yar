rule TTP_XOR_WriteProcessMemory_baa8 {
  strings:
    $key_baa8 = { ed da [2] df f8 [2] d9 cd [2] f7 cd [2] c8 d1 }

  condition:
    any of them
}