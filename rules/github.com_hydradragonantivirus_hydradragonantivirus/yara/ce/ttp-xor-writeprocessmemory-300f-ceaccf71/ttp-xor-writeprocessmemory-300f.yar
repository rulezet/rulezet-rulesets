rule TTP_XOR_WriteProcessMemory_300f {
  strings:
    $key_300f = { 67 7d [2] 55 5f [2] 53 6a [2] 7d 6a [2] 42 76 }

  condition:
    any of them
}