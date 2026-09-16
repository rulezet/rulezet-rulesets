rule TTP_XOR_WriteProcessMemory_9a43 {
  strings:
    $key_9a43 = { cd 31 [2] ff 13 [2] f9 26 [2] d7 26 [2] e8 3a }

  condition:
    any of them
}