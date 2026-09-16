rule TTP_XOR_WriteProcessMemory_62ed {
  strings:
    $key_62ed = { 35 9f [2] 07 bd [2] 01 88 [2] 2f 88 [2] 10 94 }

  condition:
    any of them
}