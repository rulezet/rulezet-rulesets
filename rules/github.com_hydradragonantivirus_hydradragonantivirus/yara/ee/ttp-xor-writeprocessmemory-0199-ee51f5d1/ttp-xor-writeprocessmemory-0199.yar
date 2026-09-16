rule TTP_XOR_WriteProcessMemory_0199 {
  strings:
    $key_0199 = { 56 eb [2] 64 c9 [2] 62 fc [2] 4c fc [2] 73 e0 }

  condition:
    any of them
}