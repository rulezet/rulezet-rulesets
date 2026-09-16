rule TTP_XOR_WriteProcessMemory_ef4a {
  strings:
    $key_ef4a = { b8 38 [2] 8a 1a [2] 8c 2f [2] a2 2f [2] 9d 33 }

  condition:
    any of them
}