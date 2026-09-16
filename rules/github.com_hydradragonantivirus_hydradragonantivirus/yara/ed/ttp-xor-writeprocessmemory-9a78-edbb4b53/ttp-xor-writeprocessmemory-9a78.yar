rule TTP_XOR_WriteProcessMemory_9a78 {
  strings:
    $key_9a78 = { cd 0a [2] ff 28 [2] f9 1d [2] d7 1d [2] e8 01 }

  condition:
    any of them
}