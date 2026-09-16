rule TTP_XOR_WriteProcessMemory_dc99 {
  strings:
    $key_dc99 = { 8b eb [2] b9 c9 [2] bf fc [2] 91 fc [2] ae e0 }

  condition:
    any of them
}