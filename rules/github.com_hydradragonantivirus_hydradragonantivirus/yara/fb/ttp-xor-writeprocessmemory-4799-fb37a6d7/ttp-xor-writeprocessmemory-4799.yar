rule TTP_XOR_WriteProcessMemory_4799 {
  strings:
    $key_4799 = { 10 eb [2] 22 c9 [2] 24 fc [2] 0a fc [2] 35 e0 }

  condition:
    any of them
}