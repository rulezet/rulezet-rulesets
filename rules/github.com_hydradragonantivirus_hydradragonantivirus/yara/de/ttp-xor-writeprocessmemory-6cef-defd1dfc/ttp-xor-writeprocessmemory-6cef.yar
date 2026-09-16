rule TTP_XOR_WriteProcessMemory_6cef {
  strings:
    $key_6cef = { 3b 9d [2] 09 bf [2] 0f 8a [2] 21 8a [2] 1e 96 }

  condition:
    any of them
}