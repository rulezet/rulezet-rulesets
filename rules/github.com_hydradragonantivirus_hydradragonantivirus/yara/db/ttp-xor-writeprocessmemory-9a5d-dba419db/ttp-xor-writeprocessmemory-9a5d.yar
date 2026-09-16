rule TTP_XOR_WriteProcessMemory_9a5d {
  strings:
    $key_9a5d = { cd 2f [2] ff 0d [2] f9 38 [2] d7 38 [2] e8 24 }

  condition:
    any of them
}