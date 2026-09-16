rule TTP_XOR_WriteProcessMemory_37ca {
  strings:
    $key_37ca = { 60 b8 [2] 52 9a [2] 54 af [2] 7a af [2] 45 b3 }

  condition:
    any of them
}