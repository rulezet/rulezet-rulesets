rule TTP_XOR_WriteProcessMemory_588e {
  strings:
    $key_588e = { 0f fc [2] 3d de [2] 3b eb [2] 15 eb [2] 2a f7 }

  condition:
    any of them
}