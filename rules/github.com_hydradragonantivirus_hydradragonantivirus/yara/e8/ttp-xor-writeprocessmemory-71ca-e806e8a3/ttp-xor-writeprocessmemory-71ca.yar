rule TTP_XOR_WriteProcessMemory_71ca {
  strings:
    $key_71ca = { 26 b8 [2] 14 9a [2] 12 af [2] 3c af [2] 03 b3 }

  condition:
    any of them
}