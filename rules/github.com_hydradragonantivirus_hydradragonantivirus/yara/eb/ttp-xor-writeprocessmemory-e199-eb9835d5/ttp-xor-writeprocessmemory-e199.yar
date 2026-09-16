rule TTP_XOR_WriteProcessMemory_e199 {
  strings:
    $key_e199 = { b6 eb [2] 84 c9 [2] 82 fc [2] ac fc [2] 93 e0 }

  condition:
    any of them
}