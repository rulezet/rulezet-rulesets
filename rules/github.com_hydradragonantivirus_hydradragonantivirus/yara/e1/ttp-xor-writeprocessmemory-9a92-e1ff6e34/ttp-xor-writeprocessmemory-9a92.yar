rule TTP_XOR_WriteProcessMemory_9a92 {
  strings:
    $key_9a92 = { cd e0 [2] ff c2 [2] f9 f7 [2] d7 f7 [2] e8 eb }

  condition:
    any of them
}