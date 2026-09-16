rule TTP_XOR_WriteProcessMemory_d199 {
  strings:
    $key_d199 = { 86 eb [2] b4 c9 [2] b2 fc [2] 9c fc [2] a3 e0 }

  condition:
    any of them
}