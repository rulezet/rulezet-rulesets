rule TTP_XOR_WriteProcessMemory_5f8e {
  strings:
    $key_5f8e = { 08 fc [2] 3a de [2] 3c eb [2] 12 eb [2] 2d f7 }

  condition:
    any of them
}