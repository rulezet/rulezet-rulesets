rule TTP_XOR_WriteProcessMemory_9a58 {
  strings:
    $key_9a58 = { cd 2a [2] ff 08 [2] f9 3d [2] d7 3d [2] e8 21 }

  condition:
    any of them
}