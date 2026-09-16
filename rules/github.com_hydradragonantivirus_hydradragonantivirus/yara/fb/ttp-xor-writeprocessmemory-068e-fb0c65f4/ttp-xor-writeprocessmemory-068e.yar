rule TTP_XOR_WriteProcessMemory_068e {
  strings:
    $key_068e = { 51 fc [2] 63 de [2] 65 eb [2] 4b eb [2] 74 f7 }

  condition:
    any of them
}