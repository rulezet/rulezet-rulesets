rule TTP_XOR_WriteProcessMemory_1fff {
  strings:
    $key_1fff = { 48 8d [2] 7a af [2] 7c 9a [2] 52 9a [2] 6d 86 }

  condition:
    any of them
}