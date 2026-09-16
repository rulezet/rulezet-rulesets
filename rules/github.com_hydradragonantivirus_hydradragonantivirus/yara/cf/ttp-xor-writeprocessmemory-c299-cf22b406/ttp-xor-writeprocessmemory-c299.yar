rule TTP_XOR_WriteProcessMemory_c299 {
  strings:
    $key_c299 = { 95 eb [2] a7 c9 [2] a1 fc [2] 8f fc [2] b0 e0 }

  condition:
    any of them
}