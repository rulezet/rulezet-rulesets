rule TTP_XOR_WriteProcessMemory_025a {
  strings:
    $key_025a = { 55 28 [2] 67 0a [2] 61 3f [2] 4f 3f [2] 70 23 }

  condition:
    any of them
}