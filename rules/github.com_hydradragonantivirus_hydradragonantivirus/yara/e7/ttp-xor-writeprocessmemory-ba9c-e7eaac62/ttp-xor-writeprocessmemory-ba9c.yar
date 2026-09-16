rule TTP_XOR_WriteProcessMemory_ba9c {
  strings:
    $key_ba9c = { ed ee [2] df cc [2] d9 f9 [2] f7 f9 [2] c8 e5 }

  condition:
    any of them
}