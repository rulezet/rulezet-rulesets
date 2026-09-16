rule TTP_XOR_WriteProcessMemory_9a9a {
  strings:
    $key_9a9a = { cd e8 [2] ff ca [2] f9 ff [2] d7 ff [2] e8 e3 }

  condition:
    any of them
}