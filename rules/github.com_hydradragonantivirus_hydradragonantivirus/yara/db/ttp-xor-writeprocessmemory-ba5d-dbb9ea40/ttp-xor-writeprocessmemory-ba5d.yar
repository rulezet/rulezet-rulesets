rule TTP_XOR_WriteProcessMemory_ba5d {
  strings:
    $key_ba5d = { ed 2f [2] df 0d [2] d9 38 [2] f7 38 [2] c8 24 }

  condition:
    any of them
}