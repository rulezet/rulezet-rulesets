rule TTP_XOR_WriteProcessMemory_6d8e {
  strings:
    $key_6d8e = { 3a fc [2] 08 de [2] 0e eb [2] 20 eb [2] 1f f7 }

  condition:
    any of them
}