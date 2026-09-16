rule TTP_XOR_WriteProcessMemory_9a10 {
  strings:
    $key_9a10 = { cd 62 [2] ff 40 [2] f9 75 [2] d7 75 [2] e8 69 }

  condition:
    any of them
}