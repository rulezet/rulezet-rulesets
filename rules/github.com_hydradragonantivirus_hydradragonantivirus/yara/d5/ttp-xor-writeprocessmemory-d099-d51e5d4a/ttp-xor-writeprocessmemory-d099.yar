rule TTP_XOR_WriteProcessMemory_d099 {
  strings:
    $key_d099 = { 87 eb [2] b5 c9 [2] b3 fc [2] 9d fc [2] a2 e0 }

  condition:
    any of them
}