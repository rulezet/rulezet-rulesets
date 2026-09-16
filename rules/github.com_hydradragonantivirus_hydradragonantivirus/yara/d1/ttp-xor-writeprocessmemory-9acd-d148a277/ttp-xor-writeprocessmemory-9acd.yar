rule TTP_XOR_WriteProcessMemory_9acd {
  strings:
    $key_9acd = { cd bf [2] ff 9d [2] f9 a8 [2] d7 a8 [2] e8 b4 }

  condition:
    any of them
}