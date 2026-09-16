rule TTP_XOR_WriteProcessMemory_9a3f {
  strings:
    $key_9a3f = { cd 4d [2] ff 6f [2] f9 5a [2] d7 5a [2] e8 46 }

  condition:
    any of them
}