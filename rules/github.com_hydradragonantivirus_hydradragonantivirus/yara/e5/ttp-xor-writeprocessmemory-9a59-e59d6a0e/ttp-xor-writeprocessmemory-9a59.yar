rule TTP_XOR_WriteProcessMemory_9a59 {
  strings:
    $key_9a59 = { cd 2b [2] ff 09 [2] f9 3c [2] d7 3c [2] e8 20 }

  condition:
    any of them
}