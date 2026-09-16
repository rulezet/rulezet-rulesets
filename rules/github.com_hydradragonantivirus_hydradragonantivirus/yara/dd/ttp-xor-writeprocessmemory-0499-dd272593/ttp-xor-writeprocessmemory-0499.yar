rule TTP_XOR_WriteProcessMemory_0499 {
  strings:
    $key_0499 = { 53 eb [2] 61 c9 [2] 67 fc [2] 49 fc [2] 76 e0 }

  condition:
    any of them
}