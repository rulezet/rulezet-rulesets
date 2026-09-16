rule TTP_XOR_WriteProcessMemory_9afd {
  strings:
    $key_9afd = { cd 8f [2] ff ad [2] f9 98 [2] d7 98 [2] e8 84 }

  condition:
    any of them
}