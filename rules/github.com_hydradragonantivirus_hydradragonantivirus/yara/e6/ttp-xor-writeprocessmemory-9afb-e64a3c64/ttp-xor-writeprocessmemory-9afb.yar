rule TTP_XOR_WriteProcessMemory_9afb {
  strings:
    $key_9afb = { cd 89 [2] ff ab [2] f9 9e [2] d7 9e [2] e8 82 }

  condition:
    any of them
}