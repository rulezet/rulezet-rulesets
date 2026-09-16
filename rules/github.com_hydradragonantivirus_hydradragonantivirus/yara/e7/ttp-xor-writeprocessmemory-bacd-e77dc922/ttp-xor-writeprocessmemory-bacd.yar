rule TTP_XOR_WriteProcessMemory_bacd {
  strings:
    $key_bacd = { ed bf [2] df 9d [2] d9 a8 [2] f7 a8 [2] c8 b4 }

  condition:
    any of them
}