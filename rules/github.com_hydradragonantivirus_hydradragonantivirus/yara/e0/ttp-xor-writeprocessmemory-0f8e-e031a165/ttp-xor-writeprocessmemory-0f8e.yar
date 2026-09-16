rule TTP_XOR_WriteProcessMemory_0f8e {
  strings:
    $key_0f8e = { 58 fc [2] 6a de [2] 6c eb [2] 42 eb [2] 7d f7 }

  condition:
    any of them
}