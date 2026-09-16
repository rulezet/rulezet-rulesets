rule TTP_XOR_WriteProcessMemory_d599 {
  strings:
    $key_d599 = { 82 eb [2] b0 c9 [2] b6 fc [2] 98 fc [2] a7 e0 }

  condition:
    any of them
}