rule TTP_XOR_WriteProcessMemory_9a04 {
  strings:
    $key_9a04 = { cd 76 [2] ff 54 [2] f9 61 [2] d7 61 [2] e8 7d }

  condition:
    any of them
}