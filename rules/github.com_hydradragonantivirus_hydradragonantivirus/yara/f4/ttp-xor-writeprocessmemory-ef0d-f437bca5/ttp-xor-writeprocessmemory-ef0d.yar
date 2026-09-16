rule TTP_XOR_WriteProcessMemory_ef0d {
  strings:
    $key_ef0d = { b8 7f [2] 8a 5d [2] 8c 68 [2] a2 68 [2] 9d 74 }

  condition:
    any of them
}