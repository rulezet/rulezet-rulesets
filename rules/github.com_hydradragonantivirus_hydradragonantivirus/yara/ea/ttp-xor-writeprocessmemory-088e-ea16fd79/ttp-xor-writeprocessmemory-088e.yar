rule TTP_XOR_WriteProcessMemory_088e {
  strings:
    $key_088e = { 5f fc [2] 6d de [2] 6b eb [2] 45 eb [2] 7a f7 }

  condition:
    any of them
}