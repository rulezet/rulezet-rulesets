rule TTP_XOR_WriteProcessMemory_bf99 {
  strings:
    $key_bf99 = { e8 eb [2] da c9 [2] dc fc [2] f2 fc [2] cd e0 }

  condition:
    any of them
}