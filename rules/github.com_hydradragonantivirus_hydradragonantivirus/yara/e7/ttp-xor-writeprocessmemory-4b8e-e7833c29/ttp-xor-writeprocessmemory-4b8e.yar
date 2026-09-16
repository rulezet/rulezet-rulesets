rule TTP_XOR_WriteProcessMemory_4b8e {
  strings:
    $key_4b8e = { 1c fc [2] 2e de [2] 28 eb [2] 06 eb [2] 39 f7 }

  condition:
    any of them
}