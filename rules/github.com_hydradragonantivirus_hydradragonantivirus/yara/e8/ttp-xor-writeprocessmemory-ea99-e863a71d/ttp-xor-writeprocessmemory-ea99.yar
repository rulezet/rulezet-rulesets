rule TTP_XOR_WriteProcessMemory_ea99 {
  strings:
    $key_ea99 = { bd eb [2] 8f c9 [2] 89 fc [2] a7 fc [2] 98 e0 }

  condition:
    any of them
}