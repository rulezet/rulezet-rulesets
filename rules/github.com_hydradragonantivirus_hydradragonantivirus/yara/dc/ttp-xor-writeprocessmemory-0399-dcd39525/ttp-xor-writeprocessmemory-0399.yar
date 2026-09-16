rule TTP_XOR_WriteProcessMemory_0399 {
  strings:
    $key_0399 = { 54 eb [2] 66 c9 [2] 60 fc [2] 4e fc [2] 71 e0 }

  condition:
    any of them
}