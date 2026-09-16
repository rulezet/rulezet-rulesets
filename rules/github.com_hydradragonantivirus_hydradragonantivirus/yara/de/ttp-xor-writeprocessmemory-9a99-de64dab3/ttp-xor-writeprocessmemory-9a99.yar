rule TTP_XOR_WriteProcessMemory_9a99 {
  strings:
    $key_9a99 = { cd eb [2] ff c9 [2] f9 fc [2] d7 fc [2] e8 e0 }

  condition:
    any of them
}