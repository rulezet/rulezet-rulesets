rule TTP_XOR_WriteProcessMemory_e60a {
  strings:
    $key_e60a = { b1 78 [2] 83 5a [2] 85 6f [2] ab 6f [2] 94 73 }

  condition:
    any of them
}