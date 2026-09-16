rule TTP_XOR_WriteProcessMemory_ff8e {
  strings:
    $key_ff8e = { a8 fc [2] 9a de [2] 9c eb [2] b2 eb [2] 8d f7 }

  condition:
    any of them
}