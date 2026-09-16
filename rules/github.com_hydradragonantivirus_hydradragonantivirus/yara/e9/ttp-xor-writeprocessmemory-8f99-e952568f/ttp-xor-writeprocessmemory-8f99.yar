rule TTP_XOR_WriteProcessMemory_8f99 {
  strings:
    $key_8f99 = { d8 eb [2] ea c9 [2] ec fc [2] c2 fc [2] fd e0 }

  condition:
    any of them
}