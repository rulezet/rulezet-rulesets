rule TTP_XOR_WriteProcessMemory_ba1d {
  strings:
    $key_ba1d = { ed 6f [2] df 4d [2] d9 78 [2] f7 78 [2] c8 64 }

  condition:
    any of them
}