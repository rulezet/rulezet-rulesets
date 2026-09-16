rule TTP_XOR_WriteProcessMemory_4f8e {
  strings:
    $key_4f8e = { 18 fc [2] 2a de [2] 2c eb [2] 02 eb [2] 3d f7 }

  condition:
    any of them
}