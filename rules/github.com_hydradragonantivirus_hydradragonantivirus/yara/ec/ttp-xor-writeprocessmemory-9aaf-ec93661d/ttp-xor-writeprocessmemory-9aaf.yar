rule TTP_XOR_WriteProcessMemory_9aaf {
  strings:
    $key_9aaf = { cd dd [2] ff ff [2] f9 ca [2] d7 ca [2] e8 d6 }

  condition:
    any of them
}