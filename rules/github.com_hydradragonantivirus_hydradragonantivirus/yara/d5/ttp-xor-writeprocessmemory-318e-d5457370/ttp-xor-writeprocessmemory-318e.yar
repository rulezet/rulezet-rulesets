rule TTP_XOR_WriteProcessMemory_318e {
  strings:
    $key_318e = { 66 fc [2] 54 de [2] 52 eb [2] 7c eb [2] 43 f7 }

  condition:
    any of them
}