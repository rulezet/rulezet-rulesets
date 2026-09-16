rule TTP_XOR_WriteProcessMemory_3f8e {
  strings:
    $key_3f8e = { 68 fc [2] 5a de [2] 5c eb [2] 72 eb [2] 4d f7 }

  condition:
    any of them
}