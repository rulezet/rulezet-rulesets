rule TTP_XOR_WriteProcessMemory_17ca {
  strings:
    $key_17ca = { 40 b8 [2] 72 9a [2] 74 af [2] 5a af [2] 65 b3 }

  condition:
    any of them
}