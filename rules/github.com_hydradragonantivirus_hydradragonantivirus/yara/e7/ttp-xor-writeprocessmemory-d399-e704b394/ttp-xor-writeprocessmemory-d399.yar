rule TTP_XOR_WriteProcessMemory_d399 {
  strings:
    $key_d399 = { 84 eb [2] b6 c9 [2] b0 fc [2] 9e fc [2] a1 e0 }

  condition:
    any of them
}