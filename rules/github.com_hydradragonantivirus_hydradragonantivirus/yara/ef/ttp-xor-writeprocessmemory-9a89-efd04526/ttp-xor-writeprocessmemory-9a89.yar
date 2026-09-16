rule TTP_XOR_WriteProcessMemory_9a89 {
  strings:
    $key_9a89 = { cd fb [2] ff d9 [2] f9 ec [2] d7 ec [2] e8 f0 }

  condition:
    any of them
}