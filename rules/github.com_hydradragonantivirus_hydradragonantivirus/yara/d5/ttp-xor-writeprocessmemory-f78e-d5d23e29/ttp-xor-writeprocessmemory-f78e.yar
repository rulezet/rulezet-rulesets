rule TTP_XOR_WriteProcessMemory_f78e {
  strings:
    $key_f78e = { a0 fc [2] 92 de [2] 94 eb [2] ba eb [2] 85 f7 }

  condition:
    any of them
}