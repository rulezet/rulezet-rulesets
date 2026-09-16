rule TTP_XOR_WriteProcessMemory_34ed {
  strings:
    $key_34ed = { 63 9f [2] 51 bd [2] 57 88 [2] 79 88 [2] 46 94 }

  condition:
    any of them
}