rule TTP_XOR_WriteProcessMemory_0208 {
  strings:
    $key_0208 = { 55 7a [2] 67 58 [2] 61 6d [2] 4f 6d [2] 70 71 }

  condition:
    any of them
}