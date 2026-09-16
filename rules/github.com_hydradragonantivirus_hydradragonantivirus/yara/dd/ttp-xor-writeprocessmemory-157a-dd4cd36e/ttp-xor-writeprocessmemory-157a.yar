rule TTP_XOR_WriteProcessMemory_157a {
  strings:
    $key_157a = { 42 08 [2] 70 2a [2] 76 1f [2] 58 1f [2] 67 03 }

  condition:
    any of them
}