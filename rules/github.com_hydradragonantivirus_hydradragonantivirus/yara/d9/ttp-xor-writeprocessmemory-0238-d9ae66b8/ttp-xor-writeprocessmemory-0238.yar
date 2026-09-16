rule TTP_XOR_WriteProcessMemory_0238 {
  strings:
    $key_0238 = { 55 4a [2] 67 68 [2] 61 5d [2] 4f 5d [2] 70 41 }

  condition:
    any of them
}