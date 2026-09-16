rule TTP_XOR_WriteProcessMemory_ba99 {
  strings:
    $key_ba99 = { ed eb [2] df c9 [2] d9 fc [2] f7 fc [2] c8 e0 }

  condition:
    any of them
}