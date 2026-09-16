rule TTP_XOR_WriteProcessMemory_9aae {
  strings:
    $key_9aae = { cd dc [2] ff fe [2] f9 cb [2] d7 cb [2] e8 d7 }

  condition:
    any of them
}