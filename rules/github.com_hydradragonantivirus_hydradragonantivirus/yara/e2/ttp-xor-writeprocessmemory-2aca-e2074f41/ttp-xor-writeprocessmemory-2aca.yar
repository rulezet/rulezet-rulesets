rule TTP_XOR_WriteProcessMemory_2aca {
  strings:
    $key_2aca = { 7d b8 [2] 4f 9a [2] 49 af [2] 67 af [2] 58 b3 }

  condition:
    any of them
}