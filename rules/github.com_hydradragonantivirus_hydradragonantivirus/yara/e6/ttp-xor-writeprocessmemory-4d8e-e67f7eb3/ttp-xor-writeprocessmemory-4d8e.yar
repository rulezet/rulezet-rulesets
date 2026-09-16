rule TTP_XOR_WriteProcessMemory_4d8e {
  strings:
    $key_4d8e = { 1a fc [2] 28 de [2] 2e eb [2] 00 eb [2] 3f f7 }

  condition:
    any of them
}