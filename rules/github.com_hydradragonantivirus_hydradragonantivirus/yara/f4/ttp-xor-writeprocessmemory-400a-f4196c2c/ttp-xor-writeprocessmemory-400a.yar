rule TTP_XOR_WriteProcessMemory_400a {
  strings:
    $key_400a = { 17 78 [2] 25 5a [2] 23 6f [2] 0d 6f [2] 32 73 }

  condition:
    any of them
}