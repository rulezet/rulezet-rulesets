rule TTP_XOR_WriteProcessMemory_f999 {
  strings:
    $key_f999 = { ae eb [2] 9c c9 [2] 9a fc [2] b4 fc [2] 8b e0 }

  condition:
    any of them
}