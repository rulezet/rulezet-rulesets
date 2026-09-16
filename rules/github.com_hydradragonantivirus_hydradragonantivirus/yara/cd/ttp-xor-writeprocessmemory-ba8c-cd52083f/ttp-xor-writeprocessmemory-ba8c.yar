rule TTP_XOR_WriteProcessMemory_ba8c {
  strings:
    $key_ba8c = { ed fe [2] df dc [2] d9 e9 [2] f7 e9 [2] c8 f5 }

  condition:
    any of them
}