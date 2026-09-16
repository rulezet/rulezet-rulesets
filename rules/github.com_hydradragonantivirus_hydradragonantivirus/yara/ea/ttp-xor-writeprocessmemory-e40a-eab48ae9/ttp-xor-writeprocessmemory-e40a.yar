rule TTP_XOR_WriteProcessMemory_e40a {
  strings:
    $key_e40a = { b3 78 [2] 81 5a [2] 87 6f [2] a9 6f [2] 96 73 }

  condition:
    any of them
}