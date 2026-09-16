rule TTP_XOR_WriteProcessMemory_eb99 {
  strings:
    $key_eb99 = { bc eb [2] 8e c9 [2] 88 fc [2] a6 fc [2] 99 e0 }

  condition:
    any of them
}