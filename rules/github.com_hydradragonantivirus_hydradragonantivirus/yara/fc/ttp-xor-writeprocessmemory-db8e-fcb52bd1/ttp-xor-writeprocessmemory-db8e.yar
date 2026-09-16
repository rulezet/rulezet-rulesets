rule TTP_XOR_WriteProcessMemory_db8e {
  strings:
    $key_db8e = { 8c fc [2] be de [2] b8 eb [2] 96 eb [2] a9 f7 }

  condition:
    any of them
}