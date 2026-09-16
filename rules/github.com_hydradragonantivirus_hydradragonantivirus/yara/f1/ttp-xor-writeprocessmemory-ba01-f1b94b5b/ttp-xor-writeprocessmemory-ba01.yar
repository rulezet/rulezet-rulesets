rule TTP_XOR_WriteProcessMemory_ba01 {
  strings:
    $key_ba01 = { ed 73 [2] df 51 [2] d9 64 [2] f7 64 [2] c8 78 }

  condition:
    any of them
}