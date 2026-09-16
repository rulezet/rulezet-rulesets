rule TTP_XOR_WriteProcessMemory_0299 {
  strings:
    $key_0299 = { 55 eb [2] 67 c9 [2] 61 fc [2] 4f fc [2] 70 e0 }

  condition:
    any of them
}