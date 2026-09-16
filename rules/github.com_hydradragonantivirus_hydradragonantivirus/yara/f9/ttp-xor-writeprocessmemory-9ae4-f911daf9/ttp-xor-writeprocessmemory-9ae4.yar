rule TTP_XOR_WriteProcessMemory_9ae4 {
  strings:
    $key_9ae4 = { cd 96 [2] ff b4 [2] f9 81 [2] d7 81 [2] e8 9d }

  condition:
    any of them
}