rule TTP_XOR_WriteProcessMemory_420a {
  strings:
    $key_420a = { 15 78 [2] 27 5a [2] 21 6f [2] 0f 6f [2] 30 73 }

  condition:
    any of them
}