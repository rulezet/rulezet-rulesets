rule TTP_XOR_WriteProcessMemory_2b8e {
  strings:
    $key_2b8e = { 7c fc [2] 4e de [2] 48 eb [2] 66 eb [2] 59 f7 }

  condition:
    any of them
}