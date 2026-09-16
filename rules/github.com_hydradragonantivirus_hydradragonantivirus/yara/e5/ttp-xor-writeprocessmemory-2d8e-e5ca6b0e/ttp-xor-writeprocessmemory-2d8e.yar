rule TTP_XOR_WriteProcessMemory_2d8e {
  strings:
    $key_2d8e = { 7a fc [2] 48 de [2] 4e eb [2] 60 eb [2] 5f f7 }

  condition:
    any of them
}