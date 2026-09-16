rule TTP_XOR_WriteProcessMemory_024a {
  strings:
    $key_024a = { 55 38 [2] 67 1a [2] 61 2f [2] 4f 2f [2] 70 33 }

  condition:
    any of them
}