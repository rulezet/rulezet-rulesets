rule TTP_XOR_WriteProcessMemory_ba97 {
  strings:
    $key_ba97 = { ed e5 [2] df c7 [2] d9 f2 [2] f7 f2 [2] c8 ee }

  condition:
    any of them
}