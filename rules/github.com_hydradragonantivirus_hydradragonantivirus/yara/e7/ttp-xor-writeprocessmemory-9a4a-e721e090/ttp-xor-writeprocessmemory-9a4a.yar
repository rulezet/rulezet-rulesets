rule TTP_XOR_WriteProcessMemory_9a4a {
  strings:
    $key_9a4a = { cd 38 [2] ff 1a [2] f9 2f [2] d7 2f [2] e8 33 }

  condition:
    any of them
}