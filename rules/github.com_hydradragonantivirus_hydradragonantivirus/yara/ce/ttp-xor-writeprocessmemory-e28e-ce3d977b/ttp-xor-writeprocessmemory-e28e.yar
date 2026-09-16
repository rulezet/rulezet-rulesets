rule TTP_XOR_WriteProcessMemory_e28e {
  strings:
    $key_e28e = { b5 fc [2] 87 de [2] 81 eb [2] af eb [2] 90 f7 }

  condition:
    any of them
}